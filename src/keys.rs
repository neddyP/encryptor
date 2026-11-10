//! Keys and passphrases: generating keys, saving them in a folder of their
//! own and printing them, reading them as typed or from a key file, and
//! asking for passphrases.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::cli::Options;
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::{self, clean_path};
use crate::term::{self, Shown, choose, choose_coded, confirm, home_path, safe, safe_path};
use crate::{history, kdf, protect, recording, session, wipe};

/// Key bytes live on the heap, locked in RAM, so moving the handle never
/// copies the key and it is never swapped out. They are zeroed when dropped.
pub type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

/// The shortest passphrase accepted, as anyone with the file can try guesses
/// at it for as long as they like.
const MIN_PASSPHRASE: usize = 12;

/// What a file is encrypted with.
pub enum Secret {
    Key(SecretKey),
    /// Made into a key once the file's header, with its salt, exists.
    Passphrase(Zeroizing<String>),
}

impl Secret {
    /// The Argon2id settings a new file's header needs, for a passphrase.
    pub fn kdf(&self) -> Option<&'static kdf::Params> {
        matches!(self, Self::Passphrase(_)).then_some(&kdf::DEFAULT)
    }

    /// For removing from shell history.
    pub fn held(&self) -> history::Secret<'_> {
        match self {
            Self::Key(key) => history::Secret::Key(key),
            Self::Passphrase(passphrase) => history::Secret::Passphrase(passphrase.as_bytes()),
        }
    }

    /// The key for a file with `header`: a copy of the key itself, or the
    /// passphrase's, made with the settings and salt in the header. A copy,
    /// so one secret can encrypt several files.
    pub fn key_for(&self, header: &[u8]) -> Result<SecretKey> {
        match self {
            Self::Key(key) => Ok(copy(key)),
            Self::Passphrase(passphrase) => kdf::key_for(passphrase.as_bytes(), header),
        }
    }
}

/// A copy of `key`, locked in RAM and zeroed when dropped like the original.
pub fn copy(key: &[u8; KEY_LEN]) -> SecretKey {
    let mut copy = new_key();
    copy.copy_from_slice(key);
    copy
}

/// What to encrypt with: a key or a passphrase.
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Key,
    Passphrase,
}

/// Asks whether to use a key or a passphrase.
pub fn choose_kind() -> Result<Kind> {
    let kind = choose_coded("Use a 256-bit key or a custom passphrase?", &[("ky", "key"), ("ps", "passphrase")])?;
    Ok(if kind == "passphrase" { Kind::Passphrase } else { Kind::Key })
}

pub enum KeySource {
    Generated { saved_to: Option<PathBuf>, printed: Printed },
    FromFile { path: PathBuf },
    Entered,
    Passphrase,
}

/// Whether a generated key was printed, and whether anything kept a copy.
#[derive(PartialEq)]
pub enum Printed {
    No,
    /// Shown and erased, with nothing found recording the session.
    Erased,
    /// Shown while the named programs were recording or sharing the session.
    Captured(String),
}

/// Shreds a freshly saved key file unless encryption completes, including
/// when the user stops part way: a key that encrypted nothing shouldn't be
/// left on disk.
#[derive(Default)]
pub struct UnusedKeyFile(Option<PathBuf>);

impl UnusedKeyFile {
    /// Keeps the key file: it has encrypted a file.
    pub fn keep(&mut self) {
        self.0 = None;
    }
}

impl Drop for UnusedKeyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0
            && wipe::shred(path).is_ok()
        {
            eprintln!("Shredded unused key file {}", safe_path(path));
        }
    }
}

/// Gets what to encrypt `input` with: the key in `--key-file`, a new one
/// saved to `--new-key`, or else a passphrase or a key, as the user chooses:
/// a new random key, saved or printed, or one they enter.
pub fn establish(input: &Path, key_file: &mut UnusedKeyFile, options: &Options) -> Result<(Secret, KeySource)> {
    if let Some(given) = from_options(input, key_file, options)? {
        return Ok(given);
    }
    let kind = choose_kind()?;
    establish_kind(kind, input, key_file)
}

/// The key `--key-file` or `--new-key` says to use, if either was given. A
/// new key in a folder is named after `input`.
pub fn from_options(
    input: &Path,
    key_file: &mut UnusedKeyFile,
    options: &Options,
) -> Result<Option<(Secret, KeySource)>> {
    if let Some(path) = &options.key_file {
        let key = read_key_file(path)?;
        return Ok(Some((Secret::Key(key), KeySource::FromFile { path: path.clone() })));
    }
    let Some(destination) = &options.new_key else { return Ok(None) };
    let key = generate()?;
    let path = match destination.is_dir() {
        true => write_key_file(&key, input, destination)?,
        false => write_key_file_at(&key, destination)?,
    };
    key_file.0 = Some(path.clone());
    if beside(&path, input) {
        eprintln!("{}", explain::key_beside_file(&path));
    }
    Ok(Some((Secret::Key(key), KeySource::Generated { saved_to: Some(path), printed: Printed::No })))
}

/// Gets a passphrase, or a key: a new random one, saved or printed, or one
/// the user enters. A saved key is named after `input`.
pub fn establish_kind(kind: Kind, input: &Path, key_file: &mut UnusedKeyFile) -> Result<(Secret, KeySource)> {
    if kind == Kind::Passphrase {
        return Ok((Secret::Passphrase(new_passphrase(true)?), KeySource::Passphrase));
    }
    if !confirm("Generate a random 256-bit key?")? {
        return enter_new_key();
    }

    let key = generate()?;
    eprintln!("Key generated (not displayed).");

    let mut saved_to = None;
    if confirm("Save the key to a file?")? {
        let to = choose_save_to(false)?;
        saved_to = Some(save(&key, input, key_file, &to)?);
    }
    let printed = if confirm("Print the key?")? { print(&key, None)? } else { Printed::No };
    let (saved_to, printed) = kept_somewhere(&key, input, key_file, saved_to, printed, None)?;
    Ok((Secret::Key(key), KeySource::Generated { saved_to, printed }))
}

/// A key the user enters for a new file, twice if it's typed.
pub fn enter_new_key() -> Result<(Secret, KeySource)> {
    let give_up = "no valid key after 3 attempts.\nRun encrypt again and answer y to have a random \
                   key generated, or enter a key of 64 characters, 0-9 and a-f.";
    let (key, _) = prompt(true, give_up)?;
    Ok((Secret::Key(key), KeySource::Entered))
}

/// How each file of a batch gets a random key of its own: saved, and where,
/// printed, or both, asked once for them all.
#[derive(Clone)]
pub struct Recipe {
    pub save: Option<SaveTo>,
    pub print: bool,
}

/// Asks how a batch of `count` files with a key each gets its keys: random
/// ones, saved or printed, or else (`None`) ones the user enters.
pub fn choose_recipe(count: usize) -> Result<Option<Recipe>> {
    if !confirm(&format!("Generate a random 256-bit key for each of the {count} files?"))? {
        return Ok(None);
    }
    let save = match confirm("Save each key to a file, named after its file?")? {
        true => Some(choose_save_to(true)?),
        false => None,
    };
    let print = confirm("Print each key?")?;
    if save.is_some() || print {
        return Ok(Some(Recipe { save, print }));
    }
    // As for one file, a key neither saved nor printed would lose its file.
    eprintln!();
    eprintln!("WARNING: keys neither saved nor printed are lost once this program exits, and");
    eprintln!("their files could never be decrypted.");
    Ok(Some(match choose("Print or save each key?", &["print", "save"])? {
        "save" => Recipe { save: Some(choose_save_to(true)?), print: false },
        _ => Recipe { save: None, print: true },
    }))
}

/// A new random key for `input`, one file of a batch, saved and printed as
/// `recipe` says.
pub fn generate_for(input: &Path, recipe: &Recipe, key_file: &mut UnusedKeyFile) -> Result<(Secret, KeySource)> {
    let key = generate()?;
    let name = input.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let saved_to = match &recipe.save {
        Some(to) => Some(save(&key, input, key_file, to)?),
        None => None,
    };
    let printed = if recipe.print { print(&key, Some(&name))? } else { Printed::No };
    let (saved_to, printed) = kept_somewhere(&key, input, key_file, saved_to, printed, Some(&name))?;
    Ok((Secret::Key(key), KeySource::Generated { saved_to, printed }))
}

/// A new passphrase for one file of a batch, named `label`.
pub fn passphrase_for(label: &str, first: bool) -> Result<(Secret, KeySource)> {
    eprintln!("Passphrase for {}:", safe(label));
    Ok((Secret::Passphrase(new_passphrase(first)?), KeySource::Passphrase))
}

/// A key that is neither saved nor printed is gone once the program exits,
/// and the file with it, so one of the two is required: asks until it's
/// done, if it isn't yet.
fn kept_somewhere(
    key: &[u8; KEY_LEN],
    input: &Path,
    key_file: &mut UnusedKeyFile,
    saved_to: Option<PathBuf>,
    printed: Printed,
    label: Option<&str>,
) -> Result<(Option<PathBuf>, Printed)> {
    if saved_to.is_some() || printed != Printed::No {
        return Ok((saved_to, printed));
    }
    eprintln!();
    eprintln!("WARNING: the key is neither saved nor printed, so once this program exits,");
    eprintln!("the encrypted file could never be decrypted.");
    loop {
        if choose("Print or save the key?", &["print", "save"])? == "save" {
            let to = choose_save_to(false)?;
            return Ok((Some(save(key, input, key_file, &to)?), Printed::No));
        }
        let printed = print(key, label)?;
        if printed != Printed::No {
            return Ok((None, printed));
        }
    }
}

/// The keys folder, as the questions name it.
fn place() -> String {
    folder().map_or_else(|| "your keys folder".into(), |dir| home_path(&dir))
}

/// Asks for a new passphrase, twice, since it's hidden as it's typed and a
/// typo would lock the file for good. It's kept as a key is, in locked memory
/// and wiped when dropped, and never saved or shown. With `advice`, first says
/// what makes a good one.
fn new_passphrase(advice: bool) -> Result<Zeroizing<String>> {
    if advice {
        eprintln!("Anyone with the encrypted file can try guesses at the passphrase, so use a long");
        eprintln!("one, such as five or more random words. It needs at least {MIN_PASSPHRASE} characters, with");
        eprintln!("a capital, a lowercase letter, a number and a special character such as ! or #.");
    }
    for _ in 0..3 {
        let passphrase = term::read_secret("Enter a passphrase: ")?;
        if let Some(problem) = weakness(&passphrase) {
            eprintln!("  {problem}");
            continue;
        }
        let again = term::read_secret("Re-enter the passphrase to confirm: ")?;
        if *again == *passphrase {
            return Ok(passphrase);
        }
        eprintln!("  The two didn't match. Type the same passphrase both times.");
    }
    Err(Error::KeyOrData(format!(
        "no passphrase after 3 attempts.\nRun encrypt again, with a passphrase of at least {MIN_PASSPHRASE} \
         characters including a capital, a lowercase letter, a number and a special character, or choose a key."
    )))
}

/// What a new passphrase lacks, if anything: enough characters, and one each
/// of a capital, a lowercase letter, a number and a special character, which
/// is anything else but a space.
fn weakness(passphrase: &str) -> Option<String> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Some(format!("That's too short: a passphrase needs at least {MIN_PASSPHRASE} characters."));
    }
    type Rule = (&'static str, fn(char) -> bool);
    let kinds: [Rule; 4] = [
        ("a capital", char::is_uppercase),
        ("a lowercase letter", char::is_lowercase),
        ("a number", char::is_numeric),
        ("a special character, such as ! or #", |c| !c.is_alphanumeric() && !c.is_whitespace()),
    ];
    let missing: Vec<&str> =
        kinds.iter().filter(|(_, has)| !passphrase.chars().any(*has)).map(|(kind, _)| *kind).collect();
    (!missing.is_empty()).then(|| format!("It also needs {}.", explain::listed(&missing)))
}

/// Asks for the passphrase a file was encrypted with. `give_up` is the error
/// if nothing is entered three times.
pub fn enter_passphrase(give_up: &str) -> Result<Zeroizing<String>> {
    for _ in 0..3 {
        let passphrase = term::read_secret("Enter the passphrase: ")?;
        if !passphrase.is_empty() {
            return Ok(passphrase);
        }
        eprintln!("  Nothing was entered.");
    }
    Err(Error::KeyOrData(give_up.into()))
}

/// Where generated keys are saved: `$XDG_DATA_HOME/encryptor/keys`, or
/// `~/.local/share/encryptor/keys`. It's away from the encrypted files, so
/// a copy of their folder, a backup or a synced folder doesn't carry the keys
/// with it, and only the user can open it.
pub fn folder() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
    Some(data.join("encryptor/keys"))
}

/// The keys folder, made if it isn't there yet, and checked to be a folder of
/// the user's own that only they can open.
fn open_folder() -> Result<PathBuf> {
    let dir = folder().ok_or_else(|| Error::File(explain::NO_KEYS_FOLDER.into()))?;
    let create_error = |e: io::Error| Error::File(explain::file(Action::Create, &dir, &e));
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(create_error)?;
    }
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(create_error(e)),
    }
    let meta = fs::symlink_metadata(&dir).map_err(create_error)?;
    // SAFETY: geteuid has no arguments and can't fail.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return Err(Error::File(explain::keys_folder_not_own(&dir)));
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(create_error)?;
    }
    Ok(dir)
}

/// Whether the key file at `key` is in the same folder as `input`, where the
/// encrypted file goes.
fn beside(key: &Path, input: &Path) -> bool {
    let folder = |path: &Path| fs::canonicalize(files::folder(path)).ok();
    folder(key).is_some_and(|dir| Some(dir) == folder(input))
}

/// Where a new key file is saved.
#[derive(Clone, Debug, PartialEq)]
pub enum SaveTo {
    /// The keys folder, named after its file.
    KeysFolder,
    /// A folder the user named, named after its file.
    Folder(PathBuf),
    /// Exactly this file, which doesn't exist yet.
    File(PathBuf),
}

/// Asks where to save a new key file: the keys folder, or a path the user
/// types, as `--new-key` takes. With `several` keys the path has to be a
/// folder, as each key is named after its file.
fn choose_save_to(several: bool) -> Result<SaveTo> {
    let files = if several { ".key files" } else { ".key file" };
    if confirm(&format!("Save the {files} to {}?", place()))? {
        return Ok(SaveTo::KeysFolder);
    }
    let prompt = match several {
        true => "Folder to save the .key files in: ",
        false => "Path to save the .key file to (a folder, or the file's full path): ",
    };
    for _ in 0..3 {
        let typed = term::read_line(prompt)?;
        if typed.is_empty() {
            eprintln!("  Nothing was entered.");
            continue;
        }
        match save_to(&clean_path(&typed), several) {
            Ok(to) => return Ok(to),
            Err(e) => eprintln!("  {e}"),
        }
    }
    Err(Error::File(format!(
        "no place to save the {files} after 3 attempts.\nRun encrypt again, and save to {} or give a {} \
         that exists and you can write to.",
        place(),
        if several { "folder" } else { "folder or path in a folder" }
    )))
}

/// Where `path`, as typed, says to save a new key: in it if it's a folder,
/// otherwise as it, if it's free and can be written there.
fn save_to(path: &Path, several: bool) -> Result<SaveTo> {
    if path.is_dir() {
        files::check_writable(&path.join("encryptor.key"))?;
        return Ok(SaveTo::Folder(path.to_path_buf()));
    }
    if several {
        return Err(Error::File(format!(
            "{} isn't a folder. Each key is named after its file, so give a folder that exists.",
            safe_path(path)
        )));
    }
    check_new_key(path)?;
    Ok(SaveTo::File(path.to_path_buf()))
}

/// Saves the key where `to` says, tells the user where, warns if that's
/// beside the encrypted file, and hands the file to `key_file` to shred if
/// encryption doesn't complete.
fn save(key: &[u8; KEY_LEN], input: &Path, key_file: &mut UnusedKeyFile, to: &SaveTo) -> Result<PathBuf> {
    let path = match to {
        SaveTo::KeysFolder => write_key_file(key, input, &open_folder()?)?,
        SaveTo::Folder(dir) => write_key_file(key, input, dir)?,
        SaveTo::File(path) => write_key_file_at(key, path)?,
    };
    key_file.0 = Some(path.clone());
    eprintln!("Key saved as: {}", home_path(&path));
    session::remember(format!("Key saved as: {}", home_path(&path)));
    if *to != SaveTo::KeysFolder && beside(&path, input) {
        eprintln!("{}", explain::key_beside_file(&path));
    }
    eprintln!("Keep it safe: anyone with it can decrypt the file, and without it no one can.");
    Ok(path)
}

/// Shows the key on the terminal and erases it afterwards, or explains why it
/// can't be shown here. If anything is recording the session, says what and
/// asks first. `label` names the file it's for, in a batch.
fn print(key: &[u8; KEY_LEN], label: Option<&str>) -> Result<Printed> {
    let captured_by = recording::warn(&recording::scan());
    if let Some(by) = &captured_by {
        // Only someone at the keyboard can agree to this, not an answer piped
        // in, which could be meant for another question or be `yes`.
        if !io::stdin().is_terminal() {
            eprintln!("Key not printed: it would be captured, and only someone at the keyboard can");
            eprintln!("agree to that. Save it to a file instead, such as with --new-key.");
            return Ok(Printed::No);
        }
        let question = format!("Printing the key would save it to {by}, compromising your encryption. Print it anyway?");
        if !confirm(&question)? {
            eprintln!("Key not printed.");
            return Ok(Printed::No);
        }
    }
    match term::show_key(key, label)? {
        Shown::Yes => match captured_by {
            Some(by) => {
                eprintln!("Key shown, then erased from the screen, but {by} captured it.");
                Ok(Printed::Captured(by))
            }
            None => {
                eprintln!("Key shown, then erased from the screen.");
                Ok(Printed::Erased)
            }
        },
        Shown::Unavailable(reason) => {
            eprintln!("  The key can't be printed here: {reason}. Save it to a file instead.");
            Ok(Printed::No)
        }
    }
}

/// Allocates a key buffer that is locked in RAM and zeroed when dropped.
pub fn new_key() -> SecretKey {
    let key: SecretKey = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    protect::lock(key.as_ptr(), KEY_LEN);
    key
}

fn generate() -> Result<SecretKey> {
    let mut key = new_key();
    getrandom::fill(&mut key[..]).map_err(explain::random_failed)?;
    Ok(key)
}

/// Writes the raw key to `<input name>.key` in `dir`, adding a number if that
/// name is taken. Only the owner can read the file.
fn write_key_file(key: &[u8; KEY_LEN], input: &Path, dir: &Path) -> Result<PathBuf> {
    let base = input
        .file_name()
        .map_or_else(|| "encryptor".into(), |n| n.to_string_lossy().into_owned());
    for n in 1..=1000 {
        let name = if n == 1 { format!("{base}.key") } else { format!("{base}.{n}.key") };
        match create_key_file(key, &dir.join(name)) {
            Err(Created::Taken) => continue,
            result => return result.map_err(|e| e.into_error()),
        }
    }
    Err(Error::File(format!(
        "there are already 1000 key files for {} in {}.\nDelete the ones you no longer need, then try again.",
        safe(&base),
        safe_path(dir)
    )))
}

/// Writes the raw key to exactly `path`, which mustn't exist yet.
fn write_key_file_at(key: &[u8; KEY_LEN], path: &Path) -> Result<PathBuf> {
    create_key_file(key, path).map_err(|e| e.into_error())
}

/// Fails before any key is made if `--new-key` couldn't be saved where asked.
pub fn check_new_key(destination: &Path) -> Result<()> {
    if destination.is_dir() {
        return crate::files::check_writable(&destination.join("encryptor.key"));
    }
    // Ending in a slash, it names a folder, which isn't there.
    if destination.as_os_str().as_bytes().ends_with(b"/") {
        return Err(Error::File(format!(
            "there's no folder {}. Make it first, or give one that exists.",
            safe_path(destination)
        )));
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err(Created::Taken.error_for(destination));
    }
    crate::files::check_writable(destination)
}

enum Created {
    /// The name is in use.
    Taken,
    Failed(Error),
}

impl Created {
    fn error_for(&self, path: &Path) -> Error {
        match self {
            Self::Taken => Error::File(format!(
                "{} already exists, so the new key wasn't saved there.\nChoose another name, or give a \
                 folder to save it in under the file's name.",
                safe_path(path)
            )),
            Self::Failed(e) => Error::File(e.to_string()),
        }
    }

    fn into_error(self) -> Error {
        match self {
            Self::Failed(e) => e,
            Self::Taken => Error::File("the key file's name is in use".into()),
        }
    }
}

fn create_key_file(key: &[u8; KEY_LEN], path: &Path) -> std::result::Result<PathBuf, Created> {
    match OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(key).and_then(|()| file.sync_all()) {
                let _ = wipe::shred(path);
                return Err(Created::Failed(Error::File(explain::file(Action::Write, path, &e))));
            }
            Ok(path.to_path_buf())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(Created::Taken),
        Err(e) => Err(Created::Failed(Error::File(explain::file(Action::Create, path, &e)))),
    }
}

/// Asks for a key, allowing three attempts, and returns it with the key file it
/// came from, if any. With `confirm_typed`, a hex key has to be entered twice:
/// the input is hidden, and encrypting with a mistyped key would make the file
/// unrecoverable. `give_up` is the error after three failed attempts.
pub fn prompt(confirm_typed: bool, give_up: &str) -> Result<(SecretKey, Option<PathBuf>)> {
    for _ in 0..3 {
        let input = term::read_secret("Enter the key (64 hex characters) or the path to its key file: ")?;
        let (key, key_file) = match parse(&input) {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("  {e}");
                continue;
            }
        };
        let typed = input.bytes().all(|b| b.is_ascii_hexdigit());
        if typed && !io::stdin().is_terminal() {
            eprintln!("note: the key came through a pipe. If you typed it into a shell");
            eprintln!("command, run `history -c` in that shell before closing it, or the");
            eprintln!("shell will save it to its history file when it exits.");
        }
        if !confirm_typed || !typed {
            return Ok((key, key_file));
        }
        let again = term::read_secret("Re-enter the key to confirm: ")?;
        if parse(&again).is_ok_and(|(k, _)| *k == *key) {
            return Ok((key, key_file));
        }
        eprintln!("  The two keys didn't match. Enter the same key both times; pasting it avoids typos.");
    }
    Err(Error::KeyOrData(give_up.into()))
}

/// Accepts 64 hex characters or the path to a 32-byte binary key file, and
/// returns the key with the key file's path, if it came from one. Error
/// messages never echo the input unless it is evidently a path, since it may
/// be a mistyped key, and the path built from it is wiped too.
fn parse(input: &str) -> std::result::Result<(SecretKey, Option<PathBuf>), String> {
    let mut key = new_key();

    if input.is_empty() {
        return Err(explain::EMPTY_KEY.into());
    }
    if input.bytes().all(|b| b.is_ascii_hexdigit()) {
        if input.len() != 2 * KEY_LEN {
            return Err(explain::hex_key_length(input.len()));
        }
        hex::decode_to_slice(input, &mut key[..]).expect("64 hex digits are 32 bytes");
        return Ok((key, None));
    }

    let path_bytes = Zeroizing::new(clean_path(input).into_os_string().into_vec());
    let (path, file) =
        find(Path::new(OsStr::from_bytes(&path_bytes))).map_err(|(path, e)| explain::not_a_key(input, &path, &e))?;
    let key = key_from_file(&path, file).map_err(|e| e.to_string())?;
    Ok((key, Some(path)))
}

/// Opens a key file: `path`, or for a bare name not found here, the file of
/// that name in the keys folder, where new keys are saved.
fn find(path: &Path) -> std::result::Result<(PathBuf, File), (PathBuf, io::Error)> {
    match File::open(path) {
        Ok(file) => Ok((path.to_path_buf(), file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound && files::parent_dir(path).as_os_str().is_empty() => {
            let saved = folder().map(|dir| dir.join(path)).filter(|saved| saved.is_file());
            match saved {
                Some(saved) => File::open(&saved).map(|file| (saved.clone(), file)).map_err(|e| (saved, e)),
                None => Err((path.to_path_buf(), e)),
            }
        }
        Err(e) => Err((path.to_path_buf(), e)),
    }
}

/// The key in a key file: 32 raw bytes, or 64 hex characters as printed, with
/// any whitespace around them. It may be a pipe, as with
/// `--key-file <(pass show keys/report)`, so its size isn't known in advance.
pub fn read_key_file(path: &Path) -> Result<SecretKey> {
    let (path, file) = find(path).map_err(|(path, e)| Error::File(explain::file(Action::Read, &path, &e)))?;
    key_from_file(&path, file)
}

fn key_from_file(path: &Path, mut file: File) -> Result<SecretKey> {
    let meta = file.metadata().map_err(|e| Error::File(explain::file(Action::Read, path, &e)))?;
    if meta.is_dir() {
        return Err(Error::File(explain::key_file_folder(path)));
    }
    // A key as hex text is at most 64 characters and a line break or two.
    let mut contents = protect::locked_zeros(2 * KEY_LEN + 3)?;
    let mut len = 0;
    while len < contents.len() {
        match file.read(&mut contents[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => protect::check()?,
            Err(e) => return Err(Error::File(explain::file(Action::Read, path, &e))),
        }
    }
    let mut key = new_key();
    if len == KEY_LEN {
        key.copy_from_slice(&contents[..KEY_LEN]);
        return Ok(key);
    }
    let text = contents[..len].trim_ascii();
    if text.len() == 2 * KEY_LEN && hex::decode_to_slice(text, &mut key[..]).is_ok() {
        return Ok(key);
    }
    let size = if meta.is_file() { meta.len() } else { len as u64 };
    Err(Error::KeyOrData(explain::key_file_size(path, size)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testing::Scratch;

    #[test]
    fn asks_passphrases_for_every_kind_of_character() {
        assert_eq!(weakness("Violet anchor 7 folds!"), None);
        assert_eq!(weakness("Ünïcode wörds 9 ‽"), None, "letters and symbols beyond ASCII count");
        assert!(weakness("Sh0rt!").unwrap().contains("too short"));
        assert_eq!(weakness("violet anchor 7 folds!").unwrap(), "It also needs a capital.");
        let missing = weakness("Violet anchor folds").unwrap();
        assert_eq!(missing, "It also needs a number and a special character, such as ! or #.");
        assert!(weakness("VIOLET ANCHOR 7 FOLDS!").unwrap().contains("a lowercase letter"));
    }

    #[test]
    fn parses_hex_keys() {
        let hex = "00112233445566778899aabbccddeeffFFEEDDCCBBAA99887766554433221100";
        let (k, key_file) = parse(hex).unwrap();
        assert_eq!((k[0], k[15], k[16], key_file), (0x00, 0xff, 0xff, None));
        assert!(parse(&hex[1..]).unwrap_err().contains("That's 1 short"));
        assert!(parse("").unwrap_err().starts_with("nothing was entered"));
        assert!(parse("not a key").unwrap_err().starts_with("that isn't a key or a key file"));
        // Mistakes are described without repeating the input.
        let spaced = format!("{} {}", &hex[..32], &hex[32..]);
        assert_eq!(parse(&spaced).unwrap_err(), "that key has spaces in it. Enter just its 64 characters of 0-9 and a-f.");
        let mut typo = hex.to_string();
        typo.replace_range(9..10, "O");
        let e = parse(&typo).unwrap_err();
        assert!(e.contains("character 10 is the letter O") && !e.contains(&typo[..9]), "{e}");
    }

    #[test]
    fn reads_key_files() {
        let dir = Scratch::new("keys-files");
        let good = dir.join("good.key");
        let bad = dir.join("bad.key");
        fs::write(&good, [9u8; KEY_LEN]).unwrap();
        fs::write(&bad, [9u8; KEY_LEN - 1]).unwrap();

        let (k, key_file) = parse(good.to_str().unwrap()).unwrap();
        assert_eq!((**k, key_file), ([9u8; KEY_LEN], Some(good.clone())));
        assert!(parse(bad.to_str().unwrap()).unwrap_err().contains("key files hold exactly 32 bytes"));
        let missing = dir.join("missing.key");
        assert!(parse(missing.to_str().unwrap()).unwrap_err().starts_with("there's no key file at"));
        assert!(parse(dir.to_str().unwrap()).unwrap_err().contains("is a folder, not a key file"));
    }

    #[test]
    fn reads_keys_written_out_as_hex() {
        let dir = Scratch::new("keys-hex");
        let key = [0xc3u8; KEY_LEN];
        for (name, contents) in [
            ("plain.txt", hex::encode(key)),
            ("line.txt", format!("{}\n", hex::encode_upper(key))),
            ("spaced.txt", format!("  {}\r\n", hex::encode(key))),
        ] {
            fs::write(dir.join(name), contents).unwrap();
            assert_eq!(**read_key_file(&dir.join(name)).unwrap(), key, "{name}");
        }
        fs::write(dir.join("short.txt"), &hex::encode(key)[1..]).unwrap();
        assert!(matches!(read_key_file(&dir.join("short.txt")), Err(Error::KeyOrData(_))));
        assert!(matches!(read_key_file(&dir.join("missing")), Err(Error::File(_))));
    }

    #[test]
    fn reads_a_key_from_a_pipe() {
        // As `--key-file <(pass show ...)` gives: a pipe, whose size isn't known.
        let mut child = std::process::Command::new("printf")
            .arg(format!("{}\\n", hex::encode([0x5au8; KEY_LEN])))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(child.stdout.as_ref().unwrap());
        let path = PathBuf::from(format!("/dev/fd/{fd}"));
        let key = read_key_file(&path);
        child.wait().unwrap();
        assert_eq!(**key.unwrap(), [0x5au8; KEY_LEN]);
    }
}
