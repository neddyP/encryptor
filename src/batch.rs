//! Several files at once. encrypt and decrypt take any number of files, and
//! with -r every file in the folders given and in their subfolders. Each file
//! is encrypted to its own .enc file beside it, with one universal key for
//! them all, named after their folder, or a separate key for each, and is
//! decrypted back the same way. decrypt -r takes one universal key only.
//!
//! Every file is checked before a key is asked for, so a problem with any of
//! them stops the run before anything is done. Then they're done in turn, and
//! the first that fails stops the rest, which are left as they were.

use std::collections::HashSet;
use std::fs;
use std::io::{self, IsTerminal};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zeroize::Zeroizing;

use crate::cli::Options;
use crate::decrypt::{self, Unlocked};
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::keys::{self, Kind, KeySource, Printed, Recipe, Secret, SecretKey, UnusedKeyFile};
use crate::report::{self, fmt_size};
use crate::term::{self, choose_coded, confirm, home_path, safe, safe_path};
use crate::progress::Overall;
use crate::{encrypt, files, history, kdf, protect, session, stream};

/// Files named one by one in the report, before the rest are counted.
const LISTED: usize = 20;

/// One universal key for every file, or a separate key for each.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Universal,
    Separate,
}

/// The files to work on, found from the names given.
struct Found {
    files: Vec<PathBuf>,
    /// What was left out of the folders, and why.
    left_out: Vec<String>,
    /// What a universal key is named after: the folder given, or else the
    /// folder the files are all in.
    name: String,
}

/// Encrypts each of the files named in `args`, and with -r every file in the
/// folders named.
pub fn encrypt(args: &[String], options: &Options) -> Result<()> {
    let found = collect("encrypt", args, options)?;
    let count = found.files.len();
    match count {
        0 => return Err(Error::File(nothing_found("encrypt", &found))),
        1 => {
            note_left_out(&found);
            return encrypt::command_path(found.files[0].clone(), options);
        }
        _ => {}
    }
    session::remember(format!("Files to encrypt: {count}"));
    if let Some(new_key) = &options.new_key {
        keys::check_new_key(new_key)?;
    }

    // Every file is checked before a key is made, as for one file. Each is
    // let go of again, so a folder of thousands doesn't hold them all open.
    let mut problems = Vec::new();
    let mut copy_on_write = Vec::new();
    let mut total = 0;
    for input in &found.files {
        protect::check()?;
        match encrypt::check(input, options) {
            Ok((original, _)) => {
                total += original.file().metadata().map_or(0, |meta| meta.len());
                if !options.keep
                    && let Some(filesystem) = files::copy_on_write(original.file())
                {
                    copy_on_write.push((input, filesystem));
                }
            }
            Err(Error::Interrupted) => return Err(Error::Interrupted),
            Err(e) => problems.push(e.to_string()),
        }
    }
    if !problems.is_empty() {
        return Err(Error::File(explain::batch_problems("encrypt", count, &problems)));
    }
    if let Some((first, filesystem)) = copy_on_write.first()
        && !encrypt::copy_on_write_ok(first, filesystem, copy_on_write.len() - 1, options)?
    {
        return Ok(());
    }

    let mut universal_file = UnusedKeyFile::default();
    let plan = plan(&found, &mut universal_file, options)?;
    let mut history_status = match &plan {
        Plan::Universal(secret, _) => vec![history::clean(secret.held())],
        Plan::Separate(_) => Vec::new(),
    };
    if !options.yes && !confirm(&format!("Encrypt {count} files using AES-256-GCM?"))? {
        eprintln!("Cancelled; nothing was encrypted.");
        return Ok(());
    }

    let started = Instant::now();
    let mut done: Vec<Sealed> = Vec::new();
    // At a terminal, one bar for the whole batch. With separate keys, each
    // file's key is made or asked for under its name, with the bar put away;
    // without a terminal, each file gets a line or two instead.
    let overall = Overall::start(count, total);
    let separate = matches!(plan, Plan::Separate(_));
    for (i, input) in found.files.iter().enumerate() {
        overall.next(input);
        if separate || !overall.active() {
            overall.pause();
            eprintln!("\n[{}/{count}] {}", i + 1, safe_path(input));
        }
        match seal(input, i == 0, &plan, &mut universal_file, &overall, options) {
            Ok(sealed) => {
                if !overall.active() {
                    eprintln!("  encrypted to {}", safe_path(&sealed.output));
                }
                overall.done(sealed.sealed.len);
                history_status.extend(sealed.history.clone());
                done.push(sealed);
            }
            Err(e) => {
                overall.pause();
                stopped("encrypted", input, done.len(), count);
                return Err(e);
            }
        }
    }
    drop(overall);
    let key_rows = batch_key_rows(&plan, &done, count);
    let history_row = match &plan {
        Plan::Separate(Each::Generate(_)) => "nothing to remove: each key was made by this run".into(),
        _ => history_summary(&history_status),
    };
    drop(plan);
    let elapsed = started.elapsed();
    if options.quiet {
        return Ok(());
    }

    let mut rows = vec![("Cipher", "AES-256-GCM (authenticated encryption)".to_string())];
    rows.extend(key_rows);
    rows.push(("File key", "derived for each file with HKDF-SHA256 from the key and its own random 256-bit salt".into()));
    let total: u64 = done.iter().map(|sealed| sealed.sealed.len).sum();
    rows.push(("Files", format!("{count} encrypted, {} in all", fmt_size(total))));
    list(
        &mut rows,
        done.iter().map(|sealed| {
            let key = match &sealed.source {
                Some(KeySource::Generated { saved_to: Some(path), .. }) => {
                    format!(" (key {})", safe(&path.file_name().unwrap_or_default().to_string_lossy()))
                }
                _ => String::new(),
            };
            format!("{} → {}{key}", safe_path(&sealed.input), safe_path(&sealed.output))
        }),
    );
    if !found.left_out.is_empty() {
        rows.push(("Left out", found.left_out.join("; ")));
    }
    rows.push(("Metadata", "stored encrypted in each file".into()));
    rows.push(("Integrity", "each verified: re-read from disk, decrypted, SHA-256 matches its original".into()));
    rows.extend(originals(&done));
    let thumbnails: Vec<usize> = done.iter().filter_map(|sealed| sealed.sealed.thumbnails).collect();
    if !thumbnails.is_empty() {
        rows.push(("Thumbnails", encrypt::thumbnails_status(thumbnails.iter().sum())));
    }
    rows.push(("Key and data", protect::memory_status().into()));
    rows.push(("Shell history", history_row));
    rows.push(("Time", format!("{elapsed:.2?}")));
    let ask = io::stdin().is_terminal() && !options.yes;
    report::show("ENCRYPTION SUCCESSFUL", &rows, "encryption-summary", ask)
}

/// What a batch is encrypted with.
enum Plan {
    /// One secret for every file.
    Universal(Secret, KeySource),
    /// A secret of its own for each file, made as it's reached.
    Separate(Each),
}

/// How each file of a batch gets a secret of its own.
#[derive(Clone, Copy)]
enum Each {
    Generate(Recipe),
    Enter,
    Passphrase,
}

/// Asks what to encrypt the batch with: the key `--key-file` or `--new-key`
/// says, or else a key or passphrase, then whether it's universal or
/// separate. A universal key saved to a file is named after the batch.
fn plan(found: &Found, universal_file: &mut UnusedKeyFile, options: &Options) -> Result<Plan> {
    let name = Path::new(&found.name);
    if let Some((secret, source)) = keys::from_options(name, universal_file, options)? {
        return Ok(Plan::Universal(secret, source));
    }
    let count = found.files.len();
    let kind = keys::choose_kind()?;
    let question = match kind {
        Kind::Key => format!("Use one universal key for all {count} files, or a separate key for each?"),
        Kind::Passphrase => format!("Use one passphrase for all {count} files, or a separate one for each?"),
    };
    Ok(match (choose_scope(&question)?, kind) {
        (Scope::Universal, kind) => {
            let (secret, source) = keys::establish_kind(kind, name, universal_file)?;
            Plan::Universal(secret, source)
        }
        (Scope::Separate, Kind::Passphrase) => Plan::Separate(Each::Passphrase),
        (Scope::Separate, Kind::Key) => Plan::Separate(match keys::choose_recipe(count)? {
            Some(recipe) => Each::Generate(recipe),
            None => Each::Enter,
        }),
    })
}

fn choose_scope(question: &str) -> Result<Scope> {
    let scope = choose_coded(question, &[("u", "universal"), ("s", "separate")])?;
    Ok(if scope == "universal" { Scope::Universal } else { Scope::Separate })
}

/// One file of a batch, encrypted.
struct Sealed {
    input: PathBuf,
    output: PathBuf,
    sealed: encrypt::Sealed,
    /// Where its own key came from, with separate keys.
    source: Option<KeySource>,
    /// What cleaning shell history of its own key or passphrase did.
    history: Option<String>,
}

/// Encrypts one file of a batch, checking it again first, as it may have
/// changed since. With separate keys, its key is made or asked for now.
fn seal(
    input: &Path,
    first: bool,
    plan: &Plan,
    universal_file: &mut UnusedKeyFile,
    overall: &Overall,
    options: &Options,
) -> Result<Sealed> {
    let (original, output) = encrypt::check(input, options)?;
    let (sealed, source, history) = match plan {
        Plan::Universal(secret, _) => {
            (encrypt::seal(input, &output, original, secret, universal_file, options.keep)?, None, None)
        }
        Plan::Separate(each) => {
            let mut own_file = UnusedKeyFile::default();
            let name = input.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let (secret, source) = match each {
                Each::Generate(recipe) => keys::generate_for(input, *recipe, &mut own_file)?,
                Each::Enter => {
                    eprintln!("Key for {}:", safe(&name));
                    keys::enter_new_key()?
                }
                Each::Passphrase => keys::passphrase_for(&name, first)?,
            };
            // A key just generated can't be in shell history.
            let history = (!matches!(each, Each::Generate(_))).then(|| history::clean(secret.held()));
            overall.resume();
            let sealed = encrypt::seal(input, &output, original, &secret, &mut own_file, options.keep)?;
            (sealed, Some(source), history)
        }
    };
    Ok(Sealed { input: input.to_path_buf(), output, sealed, source, history })
}

/// The report's rows on the batch's keys and where they're kept.
fn batch_key_rows(plan: &Plan, done: &[Sealed], count: usize) -> Vec<(&'static str, String)> {
    match plan {
        Plan::Universal(_, source) => {
            let [(label, key), storage] = encrypt::key_rows(source);
            let all = match source {
                KeySource::Passphrase => format!(", one passphrase for all {count} files"),
                _ => format!(", one universal key for all {count} files"),
            };
            vec![(label, key + &all), storage]
        }
        Plan::Separate(Each::Generate(_)) => vec![
            ("Key", "256-bit, a separate one for each file, generated by the OS CSPRNG".into()),
            ("Key storage", separate_storage(done)),
        ],
        Plan::Separate(Each::Enter) => vec![
            ("Key", "256-bit, a separate one for each file, entered by you".into()),
            ("Key storage", "not stored by this tool".into()),
        ],
        Plan::Separate(Each::Passphrase) => vec![
            ("Key", format!("256-bit, from a separate passphrase for each file, with {}", kdf::DEFAULT.summary())),
            ("Key storage", "your passphrases; not stored by this tool".into()),
        ],
    }
}

/// The report's rows on what became of the originals: one for those dealt
/// with as planned, then a row for each that wasn't.
fn originals(done: &[Sealed]) -> Vec<(&'static str, String)> {
    let warned = |sealed: &&Sealed| sealed.sealed.original.starts_with("WARNING");
    let mut rows = Vec::new();
    let fine: Vec<&Sealed> = done.iter().filter(|sealed| !warned(sealed)).collect();
    if let Some(first) = fine.first() {
        let which = if fine.len() == done.len() { format!("all {}", done.len()) } else { fine.len().to_string() };
        rows.push(("Originals", format!("{which}: {}", first.sealed.original)));
    }
    for sealed in done.iter().filter(warned) {
        let label = if rows.is_empty() { "Originals" } else { "" };
        rows.push((label, format!("{}: {}", safe_path(&sealed.input), sealed.sealed.original)));
    }
    rows
}

/// Decrypts each of the files named in `args`, and with -r every .enc file
/// in the folders named, with one universal key.
pub fn decrypt(args: &[String], options: &Options) -> Result<()> {
    let found = collect("decrypt", args, options)?;
    let count = found.files.len();
    match count {
        0 => return Err(Error::File(nothing_found("decrypt", &found))),
        1 => {
            note_left_out(&found);
            return decrypt::command_path(found.files[0].clone(), options);
        }
        _ => {}
    }
    session::remember(format!("Files to decrypt: {count}"));

    // Every file is checked before a key is asked for, and what each was
    // encrypted with is noted.
    let mut problems = Vec::new();
    let mut passphrases = 0;
    let mut existing = Vec::new();
    let mut total = 0;
    for input in &found.files {
        protect::check()?;
        let output = files::decrypted_path(input);
        let checked = decrypt::open("decrypt", input)
            .and_then(|encrypted| Ok((encrypted.version, encrypted.len, decrypt::check_output(input, &output)?)));
        match checked {
            Ok((version, len, replace)) => {
                total += len;
                passphrases += usize::from(version == stream::PASSPHRASE_VERSION);
                if replace {
                    existing.push(output);
                }
            }
            Err(Error::Interrupted) => return Err(Error::Interrupted),
            Err(e) => problems.push(e.to_string()),
        }
    }
    if !problems.is_empty() {
        return Err(Error::File(explain::batch_problems("decrypt", count, &problems)));
    }
    // Replacing files is never agreed to through a pipe, as for one file.
    let interactive = io::stdin().is_terminal();
    if let Some(first) = existing.first()
        && !options.overwrite
        && !interactive
    {
        return Err(Error::Usage(explain::needs_overwrite(first)));
    }

    let keys_used = count - passphrases;
    let mixed = passphrases > 0 && keys_used > 0;
    let scope = if options.recursive || options.key_file.is_some() {
        if mixed {
            return Err(Error::Usage(explain::mixed_kinds(passphrases, keys_used, options.recursive)));
        }
        Scope::Universal
    } else if mixed {
        eprintln!("{passphrases} of the files use a passphrase and {keys_used} a key, so each is asked for in turn.");
        Scope::Separate
    } else if passphrases == count {
        choose_scope(&format!("Were all {count} files encrypted with one passphrase, or each with a separate one?"))?
    } else {
        choose_scope(&format!("Were all {count} files encrypted with one universal key, or each with a separate key?"))?
    };

    let mut history_status = Vec::new();
    let opener = match scope {
        Scope::Separate => None,
        Scope::Universal if passphrases == count => {
            if options.key_file.is_some() {
                return Err(Error::Usage(explain::PASSPHRASE_NOT_KEY.into()));
            }
            let passphrase = keys::enter_passphrase(
                "no passphrase entered.\nRun decrypt again, and enter the passphrase the files were encrypted with.",
            )?;
            history_status.push(history::clean(history::Secret::Passphrase(passphrase.as_bytes())));
            Some(Opener::Passphrase(passphrase))
        }
        Scope::Universal => {
            let (key, key_file) = match &options.key_file {
                Some(path) => (keys::read_key_file(path)?, Some(path.clone())),
                None => keys::prompt(
                    false,
                    &format!(
                        "no valid key after 3 attempts.\nRun decrypt again with the files' key: the 64 characters \
                         printed when they were encrypted, or its key file, usually {}.key.",
                        safe(&found.name)
                    ),
                )?,
            };
            history_status.push(history::clean(history::Secret::Key(&key)));
            Some(Opener::Key(key, key_file))
        }
    };

    if !options.yes && !confirm(&format!("Decrypt {count} files using AES-256-GCM?"))? {
        eprintln!("Cancelled; nothing was decrypted.");
        return Ok(());
    }
    if let Some(first) = existing.first()
        && !options.overwrite
    {
        let question = match existing.len() {
            1 => format!("{} already exists. Overwrite it?", safe_path(first)),
            n => format!("{n} of the decrypted files already exist, such as {}. Overwrite them?", safe_path(first)),
        };
        if !confirm(&question)? {
            eprintln!("Cancelled; nothing was written.");
            return Ok(());
        }
    }
    let overwrite = options.overwrite || !existing.is_empty();

    let started = Instant::now();
    let mut done: Vec<Opened> = Vec::new();
    // As for encrypting: one bar at a terminal, put away while a separate
    // key or passphrase is asked for.
    let overall = Overall::start(count, total);
    for (i, input) in found.files.iter().enumerate() {
        overall.next(input);
        if opener.is_none() || !overall.active() {
            overall.pause();
            eprintln!("\n[{}/{count}] {}", i + 1, safe_path(input));
        }
        match unseal(input, opener.as_ref(), &overall, options, overwrite) {
            Ok(opened) => {
                if !overall.active() {
                    eprintln!("  decrypted to {}", safe_path(&opened.output));
                }
                overall.done(opened.len);
                history_status.extend(opened.history.clone());
                done.push(opened);
            }
            Err(e) => {
                overall.pause();
                stopped("decrypted", input, done.len(), count);
                return Err(e);
            }
        }
    }
    drop(overall);
    let elapsed = started.elapsed();
    if options.quiet {
        return Ok(());
    }

    let key = match &opener {
        Some(Opener::Key(_, Some(path))) => {
            format!("256-bit, from {}, one universal key for all {count} files", safe_path(path))
        }
        Some(Opener::Key(_, None)) => format!("256-bit, entered by you, one universal key for all {count} files"),
        Some(Opener::Passphrase(_)) => {
            format!("{}, one passphrase for all {count} files", decrypt::key_row(&done[0].start, true))
        }
        None => "256-bit, a separate key or passphrase for each file".into(),
    };
    drop(opener);
    let total: u64 = done.iter().map(|opened| opened.opened.len).sum();
    let mut rows = vec![
        ("Cipher", "AES-256-GCM (authenticated encryption)".to_string()),
        ("Key", key),
        ("Auth tags", "128-bit, every one valid: each file is authentic and uncorrupted".into()),
        ("Files", format!("{count} decrypted, {} in all; the .enc files are kept", fmt_size(total))),
    ];
    list(
        &mut rows,
        done.iter().map(|opened| {
            let replaced = decrypt::replaced_note(opened.opened.replaced);
            format!("{} → {}{replaced}", safe_path(&opened.input), safe_path(&opened.output))
        }),
    );
    if !found.left_out.is_empty() {
        rows.push(("Left out", found.left_out.join("; ")));
    }
    rows.push(("Integrity", "each verified: re-read from disk, SHA-256 matches its decrypted data".into()));
    rows.push(("Metadata", grouped(done.iter().map(|opened| opened.opened.metadata.as_str()))));
    rows.push(("Key and data", protect::memory_status().into()));
    rows.push(("Shell history", history_summary(&history_status)));
    rows.push(("Time", format!("{elapsed:.2?}")));
    report::show("DECRYPTION SUCCESSFUL", &rows, "decryption-summary", interactive && !options.yes)
}

/// What a batch is decrypted with, when it's one for all the files.
enum Opener {
    Key(SecretKey, Option<PathBuf>),
    /// Made into each file's key with the settings and salt in its header.
    Passphrase(Zeroizing<String>),
}

/// One file of a batch, decrypted.
struct Opened {
    input: PathBuf,
    output: PathBuf,
    opened: decrypt::Opened,
    /// The encrypted file's length.
    len: u64,
    /// Its header, which describes the key it needs.
    start: Vec<u8>,
    /// What cleaning shell history of its own key or passphrase did.
    history: Option<String>,
}

/// Decrypts one file of a batch next to it, opening it again, as it may have
/// changed since it was checked. Without `opener`, its key or passphrase is
/// asked for now. `overwrite` says a file already where it goes may be
/// replaced.
fn unseal(
    input: &Path,
    opener: Option<&Opener>,
    overall: &Overall,
    options: &Options,
    overwrite: bool,
) -> Result<Opened> {
    let encrypted = decrypt::open("decrypt", input)?;
    let output = files::decrypted_path(input);
    let replace = decrypt::check_output(input, &output)?;
    if replace && !overwrite {
        return Err(Error::Usage(explain::needs_overwrite(&output)));
    }
    let unlocked = match opener {
        Some(Opener::Key(key, key_file)) => {
            Unlocked { key: keys::copy(key), key_file: key_file.clone(), passphrase: false, history: String::new() }
        }
        Some(Opener::Passphrase(passphrase)) => Unlocked {
            key: kdf::key_for(passphrase.as_bytes(), &encrypted.start)?,
            key_file: None,
            passphrase: true,
            history: String::new(),
        },
        None => decrypt::key(options, "decrypt", &output, &encrypted)?,
    };
    overall.resume();
    let len = encrypted.len;
    let start = encrypted.start.clone();
    let opened = decrypt::unseal(input, &output, encrypted, &unlocked, replace)?;
    let history = opener.is_none().then(|| unlocked.history.clone());
    Ok(Opened { input: input.to_path_buf(), output, opened, len, start, history })
}

/// Finds the files `command` works on: those named, and with -r every file
/// in the folders named and in their subfolders. Asks for one if none was
/// named.
fn collect(command: &str, args: &[String], options: &Options) -> Result<Found> {
    let mut paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    if paths.is_empty() {
        let what = if options.recursive { "Folder" } else { "File" };
        let raw = term::read_line(&format!("{what} to {command}: "))?;
        if raw.is_empty() {
            return Err(Error::Usage(explain::no_file_given(command)));
        }
        paths.push(files::clean_path(&raw));
    }
    let id = |path: &Path| fs::metadata(path).ok().map(|meta| (meta.dev(), meta.ino()));
    let mut walk = Walk {
        encrypting: command == "encrypt",
        keys_folder: keys::folder().and_then(|dir| id(&dir)),
        key_file: options.key_file.as_deref().and_then(id),
        seen: HashSet::new(),
        files: Vec::new(),
        left_out: LeftOut::default(),
    };
    let mut folders = Vec::new();
    for path in &paths {
        let meta = fs::symlink_metadata(path).map_err(|e| Error::File(explain::missing(command, path, &e)))?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            return Err(Error::File(explain::symlink(command, path)));
        }
        if kind.is_dir() {
            if !options.recursive {
                return Err(Error::File(explain::folder_needs_r(command, path)));
            }
            folders.push(path.clone());
            walk.folder(path)?;
        } else if kind.is_file() {
            walk.add(path.clone(), &meta);
        } else {
            return Err(Error::File(explain::special(path, kind)));
        }
    }
    let name = match (paths.len(), folders.as_slice()) {
        (1, [folder]) => name_of(folder),
        _ => common_folder(&walk.files).and_then(|dir| name_of(&dir)),
    };
    Ok(Found {
        files: walk.files,
        left_out: walk.left_out.describe(),
        name: name.filter(|name| !name.is_empty()).unwrap_or_else(|| "files".into()),
    })
}

/// Going through folders for the files in them.
struct Walk {
    encrypting: bool,
    /// The keys folder, which is never gone into, as its keys open the
    /// files: encrypted, they'd be locked inside what they open.
    keys_folder: Option<(u64, u64)>,
    /// The key file in use, which is left out for the same reason.
    key_file: Option<(u64, u64)>,
    /// Every file taken in, so one named twice, or named and in a folder
    /// named, is only done once.
    seen: HashSet<(u64, u64)>,
    files: Vec<PathBuf>,
    left_out: LeftOut,
}

impl Walk {
    /// Takes in a file, unless it's in already or is the key in use.
    fn add(&mut self, path: PathBuf, meta: &fs::Metadata) {
        let id = (meta.dev(), meta.ino());
        if Some(id) == self.key_file {
            self.left_out.key_file = true;
        } else if self.seen.insert(id) {
            self.files.push(path);
        }
    }

    /// Takes in the files in `dir` and its subfolders, in name order. Links
    /// aren't followed, so nothing outside the folder is reached through one.
    /// Encrypting leaves out files already ending in .enc; decrypting takes
    /// only those.
    fn folder(&mut self, dir: &Path) -> Result<()> {
        let read_error = |e| Error::File(explain::file(Action::Read, dir, &e));
        let mut entries = fs::read_dir(dir)
            .map_err(read_error)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<PathBuf>>>()
            .map_err(read_error)?;
        entries.sort();
        for path in entries {
            protect::check()?;
            let meta =
                fs::symlink_metadata(&path).map_err(|e| Error::File(explain::file(Action::Read, &path, &e)))?;
            let kind = meta.file_type();
            let encrypted = path.extension().is_some_and(|ext| ext == "enc");
            if kind.is_symlink() {
                self.left_out.links += 1;
            } else if kind.is_dir() {
                if Some((meta.dev(), meta.ino())) == self.keys_folder {
                    self.left_out.keys_folder = true;
                } else {
                    self.folder(&path)?;
                }
            } else if !kind.is_file() {
                self.left_out.special += 1;
            } else if self.encrypting && encrypted {
                self.left_out.encrypted += 1;
            } else if !self.encrypting && !encrypted {
                self.left_out.plain += 1;
            } else {
                self.add(path, &meta);
            }
        }
        Ok(())
    }
}

/// What going through the folders left out.
#[derive(Default)]
struct LeftOut {
    links: usize,
    special: usize,
    /// Files already ending in .enc, when encrypting.
    encrypted: usize,
    /// Files not ending in .enc, when decrypting.
    plain: usize,
    keys_folder: bool,
    key_file: bool,
}

impl LeftOut {
    fn describe(&self) -> Vec<String> {
        let files = |n: usize| if n == 1 { "1 file".to_string() } else { format!("{n} files") };
        let mut notes = Vec::new();
        if self.encrypted > 0 {
            notes.push(format!("{} already ending in .enc", files(self.encrypted)));
        }
        if self.plain > 0 {
            notes.push(format!("{} not ending in .enc", files(self.plain)));
        }
        if self.links > 0 {
            let links = if self.links == 1 { "1 symbolic link".into() } else { format!("{} symbolic links", self.links) };
            notes.push(format!("{links}, not followed"));
        }
        if self.special > 0 {
            notes.push(format!("{} that aren't regular files", files(self.special)));
        }
        if self.keys_folder {
            notes.push("the keys folder, as its keys open the files".into());
        }
        if self.key_file {
            notes.push("the key file in use".into());
        }
        notes
    }
}

/// The name of a folder, as it really is, so `.` is named too.
fn name_of(dir: &Path) -> Option<String> {
    let real = fs::canonicalize(dir).ok()?;
    real.file_name().map(|name| name.to_string_lossy().into_owned())
}

/// The deepest folder all of `files` are in, if they share one.
fn common_folder(files: &[PathBuf]) -> Option<PathBuf> {
    let folders: Vec<PathBuf> = files.iter().filter_map(|file| fs::canonicalize(files::folder(file)).ok()).collect();
    let mut common = folders.first()?.clone();
    for folder in &folders[1..] {
        while !folder.starts_with(&common) {
            if !common.pop() {
                return None;
            }
        }
    }
    Some(common)
}

fn note_left_out(found: &Found) {
    if !found.left_out.is_empty() {
        eprintln!("Left out: {}.", found.left_out.join("; "));
    }
}

fn nothing_found(command: &str, found: &Found) -> String {
    let what = if command == "encrypt" { "There are no files to encrypt" } else { "There are no .enc files to decrypt" };
    match found.left_out.is_empty() {
        true => format!("{what} there."),
        false => format!("{what} there. Left out: {}.", found.left_out.join("; ")),
    }
}

/// Says where a batch stopped, before the error that stopped it.
fn stopped(what: &str, at: &Path, done: usize, count: usize) {
    let rest = count - done - 1;
    eprintln!(
        "\nStopped at {}: {done} of the {count} files were {what} before it, and the {rest} after it weren't touched.",
        safe_path(at)
    );
}

/// Adds a line to the report for each of `lines`, up to `LISTED`, then counts
/// the rest.
fn list(rows: &mut Vec<(&'static str, String)>, lines: impl ExactSizeIterator<Item = String>) {
    let total = lines.len();
    rows.extend(lines.take(LISTED).map(|line| ("", line)));
    if total > LISTED {
        rows.push(("", format!("...and {} more", total - LISTED)));
    }
}

/// Statuses that may differ from file to file, each with how many had it,
/// the most common few only.
fn grouped<'a>(statuses: impl Iterator<Item = &'a str>) -> String {
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for status in statuses {
        match groups.iter_mut().find(|(seen, _)| *seen == status) {
            Some((_, n)) => *n += 1,
            None => groups.push((status, 1)),
        }
    }
    groups.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    if let [(only, n)] = groups.as_slice() {
        return format!("all {n}: {only}");
    }
    let mut parts: Vec<String> = groups.iter().take(3).map(|(status, n)| format!("{n}: {status}")).collect();
    let others: usize = groups.iter().skip(3).map(|(_, n)| n).sum();
    if others > 0 {
        parts.push(format!("{others} otherwise"));
    }
    parts.join("; ")
}

/// What cleaning shell history did over a batch: the removals, or that there
/// were none.
fn history_summary(statuses: &[String]) -> String {
    let removed: Vec<&str> =
        statuses.iter().map(String::as_str).filter(|status| !status.starts_with("no entries")).collect();
    match (removed.as_slice(), statuses.first()) {
        ([], Some(first)) => first.clone(),
        ([], None) => "nothing to remove".into(),
        (removed, _) => removed.join("; "),
    }
}

/// Where the keys of a batch with separate generated keys went.
fn separate_storage(done: &[Sealed]) -> String {
    let (mut saved, mut shown) = (0, 0);
    let mut captured = Vec::new();
    for sealed in done {
        let Some(KeySource::Generated { saved_to, printed }) = &sealed.source else { continue };
        saved += usize::from(saved_to.is_some());
        match printed {
            Printed::Erased => shown += 1,
            Printed::Captured(by) => captured.push(format!("{} (by {by})", safe_path(&sealed.input))),
            Printed::No => {}
        }
    }
    let keys = |n: usize| if n == 1 { "1 key".to_string() } else { format!("{n} keys") };
    let mut parts = Vec::new();
    if saved > 0 {
        let place = keys::folder().map_or_else(|| "the keys folder".into(), |dir| home_path(&dir));
        parts.push(format!("{} saved in {place}, each named after its file (owner read/write only)", keys(saved)));
    }
    if shown > 0 {
        parts.push(format!("{} shown once on screen, then erased", keys(shown)));
    }
    if !captured.is_empty() {
        parts.push(format!(
            "WARNING: the keys for {} were captured as they were shown: anyone with that copy can decrypt those files",
            captured.join(", ")
        ));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    fn options(recursive: bool) -> Options {
        Options { recursive, ..Options::default() }
    }

    fn args(paths: &[&Path]) -> Vec<String> {
        paths.iter().map(|path| path.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn finds_every_file_in_a_folder_and_its_subfolders() {
        let dir = Scratch::new("batch-walk");
        let docs = dir.join("docs");
        fs::create_dir_all(docs.join("sub/deeper")).unwrap();
        for name in ["b.txt", ".hidden", "sub/a.pdf", "sub/deeper/c.md", "old.enc"] {
            fs::write(docs.join(name), b"x").unwrap();
        }
        std::os::unix::fs::symlink(docs.join("b.txt"), docs.join("link")).unwrap();

        let found = collect("encrypt", &args(&[&docs]), &options(true)).unwrap();
        let names: Vec<&Path> = found.files.iter().map(|file| file.strip_prefix(&docs).unwrap()).collect();
        assert_eq!(names, [".hidden", "b.txt", "sub/a.pdf", "sub/deeper/c.md"].map(Path::new));
        assert_eq!(found.name, "docs");
        assert_eq!(found.left_out, ["1 file already ending in .enc", "1 symbolic link, not followed"]);

        // Decrypting takes the .enc files only.
        let found = collect("decrypt", &args(&[&docs]), &options(true)).unwrap();
        assert_eq!(found.files, [docs.join("old.enc")]);
        assert_eq!(found.left_out, ["4 files not ending in .enc", "1 symbolic link, not followed"]);
    }

    #[test]
    fn needs_r_for_a_folder_and_takes_each_file_once() {
        let dir = Scratch::new("batch-names");
        let docs = dir.join("docs");
        fs::create_dir_all(&docs).unwrap();
        let (a, b) = (docs.join("a.txt"), dir.join("b.txt"));
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();
        assert!(matches!(
            collect("encrypt", &args(&[&docs]), &options(false)),
            Err(Error::File(e)) if e.contains("add -r")
        ));

        // Named twice, and named as well as in a folder named.
        let found = collect("encrypt", &args(&[&a, &docs, &a, &b]), &options(true)).unwrap();
        assert_eq!(found.files, [a, b]);
        // Named after the folder they're all in.
        assert_eq!(found.name, name_of(&dir).unwrap());
    }

    #[test]
    fn leaves_out_the_key_in_use() {
        let dir = Scratch::new("batch-key");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        fs::write(dir.join("k.key"), [1u8; 32]).unwrap();
        let options = Options { recursive: true, key_file: Some(dir.join("k.key")), ..Options::default() };
        let found = collect("encrypt", &args(&[&dir]), &options).unwrap();
        assert_eq!(found.files, [dir.join("a.txt")]);
        assert_eq!(found.left_out, ["the key file in use"]);
    }

    #[test]
    fn finds_the_folder_files_share() {
        let dir = Scratch::new("batch-common");
        for name in ["x/a", "x/y/b", "z/c"] {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"").unwrap();
        }
        let real = fs::canonicalize(&dir).unwrap();
        assert_eq!(common_folder(&[dir.join("x/a"), dir.join("x/y/b")]), Some(real.join("x")));
        assert_eq!(common_folder(&[dir.join("x/a"), dir.join("z/c")]), Some(real));
        assert_eq!(common_folder(&[]), None);
    }

    #[test]
    fn sums_up_what_happened_to_each_file() {
        assert_eq!(grouped(["same", "same"].into_iter()), "all 2: same");
        assert_eq!(grouped(["a", "b", "b", "c", "d", "e"].into_iter()), "2: b; 1: a; 1: c; 2 otherwise");
        let none = "no entries held the passphrase".to_string();
        assert_eq!(history_summary(&[none.clone(), none.clone()]), none);
        let removed = "removed 1 entry holding the passphrase, from ~/.bash_history".to_string();
        assert_eq!(history_summary(&[none, removed.clone()]), removed);
    }
}
