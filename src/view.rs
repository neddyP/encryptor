//! The view command: an encrypted file decrypted into locked memory and shown
//! on a screen of its own until Enter, then erased from the screen and
//! encrypted again, into the current folder, with the same key or a new one
//! as the user chooses. The decrypted file is only ever in locked memory and
//! on the terminal: if anything the plaintext would go in can't be locked,
//! the run stops before putting it there. The encrypted file is left as it
//! is until the new one has been read back from disk and checked.

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::cli::Options;
use crate::decrypt::{self, Encrypted};
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::{self, PartFile};
use crate::keys::{self, KeySource, SecretKey, UnusedKeyFile};
use crate::meta::Metadata;
use crate::report::{self, fmt_size};
use crate::term::{self, choose, confirm, safe_path};
use crate::{KEY_LEN, encrypt, history, pager, protect, recording, session, stream, timestamps};

/// Locked memory needed beyond the file itself: the stack, the chunk being
/// decrypted, the screen being drawn, the key and the answers typed.
const LOCK_MARGIN: u64 = 1 << 20;

/// A file decrypted and shown, to be encrypted again.
struct Viewed {
    /// The encrypted file it came from.
    input: PathBuf,
    /// Its name decrypted, which a new key file is named after.
    plain_name: PathBuf,
    contents: Zeroizing<Vec<u8>>,
    metadata: Option<Metadata>,
    /// How it was shown, for the report.
    shown: String,
    history: String,
}

pub fn command(file: Option<&str>, options: &Options) -> Result<()> {
    // Someone at the keyboard says when they're done and which key to
    // encrypt it with again, and the file needs a terminal it can be erased
    // from. Both are checked before a key is asked for.
    if !io::stdin().is_terminal() {
        return Err(Error::Usage(explain::view_needs_keyboard()));
    }
    if let Err(reason) = term::open_screen() {
        return Err(Error::Message(explain::cant_view_here(reason)));
    }
    let input = files::file_path("view", file)?;
    let encrypted = decrypt::open("view", &input)?;

    // The whole file is held in locked memory, so it has to fit in what can
    // still be locked, with room to work in. If it doesn't, it can be
    // decrypted to a file instead, which streams it.
    let room = protect::lockable().map(|free| free.saturating_sub(LOCK_MARGIN)).filter(|&room| room < pager::MAX_LEN);
    if encrypted.len > room.unwrap_or(pager::MAX_LEN) {
        let output = files::decrypted_path(&input);
        eprintln!("{}", explain::too_large_to_view(&input, encrypted.len, room, &output));
        drop(encrypted);
        return match choose("Decrypt it to a file, or quit?", &["decrypt", "quit"])? {
            "decrypt" => decrypt::command(Some(&input.to_string_lossy()), options),
            _ => {
                eprintln!("Nothing was decrypted.");
                Ok(())
            }
        };
    }

    // Once it's been shown, it's encrypted again into the current folder, so
    // that has to be possible before anything is asked.
    let here = std::env::current_dir().map_err(|e| Error::File(explain::no_working_folder(&e)))?;
    let name = PathBuf::from(input.file_name().unwrap_or_default());
    let plain_name = files::decrypted_path(&name);
    let output = output_path(&input, &here, &name, &plain_name)?;
    files::can_create(&output).map_err(|e| Error::File(explain::view_cant_write(&output, &e)))?;

    // From here on, if anything the plaintext would go in can't be locked,
    // the run stops before putting it there. What hashing, the cipher and
    // formatting leave on the stack is locked too, and so is the key.
    protect::require_locking();
    protect::lock_stack();
    protect::check_locked()?;
    session::remember(format!("File to view: {}", safe_path(&input)));

    let (key, key_file) = decrypt::key(options, "encryptor view", &plain_name)?;
    let history = history::clean(Some(&key));
    // Looked for before the file is decrypted, as looking can start other
    // programs, so none is started while the plaintext is in memory.
    let recorders = recording::scan();
    let (metadata, contents) = decrypt_to_memory(encrypted, &key, &input, key_file.as_deref())?;

    eprintln!("\n{}", explain::BEFORE_VIEWING);
    // Only someone at the keyboard can agree to this, as with printing a key.
    let captured_by = recording::warn(&recorders);
    let question = match &captured_by {
        Some(by) => format!("Showing the file would save its contents to {by}. Show it anyway?"),
        None => "Show the decrypted file?".into(),
    };
    if !confirm(&question)? {
        eprintln!("Not shown; nothing was written.");
        return Ok(());
    }
    pager::show(&contents, &safe_path(&name))?;
    let shown = match &captured_by {
        Some(by) => {
            eprintln!("The file was shown, then erased from the screen, but {by} captured it.");
            format!("shown on screen and captured by {by}: anyone with that copy can read it")
        }
        None => {
            eprintln!("The file was shown, then erased from the screen.");
            "shown on screen, then erased".into()
        }
    };

    eprintln!();
    match (files::same_file(&input, &output), here.join(&name) == output) {
        (true, _) => eprintln!("Now it's encrypted again, replacing {}:", safe_path(&output)),
        (false, true) => eprintln!("Now it's encrypted again, as {}:", safe_path(&output)),
        (false, false) => eprintln!(
            "Now it's encrypted again, as {}, since {} is another file:",
            safe_path(&output),
            safe_path(&here.join(&name))
        ),
    }
    match &key_file {
        Some(path) => eprintln!("  s  with the same key, from {}", safe_path(path)),
        None => eprintln!("  s  with the same key you entered"),
    }
    eprintln!("  n  with a new key");
    let same_key = choose("Same key or a new one?", &["same", "new"])? == "same";
    let viewed = Viewed { input, plain_name, contents, metadata, shown, history };
    reencrypt(viewed, key, key_file, same_key, &output, options)
}

/// Where the file viewed is encrypted again: under its own name in the
/// current folder `here`, replacing it if it's there, or if another file has
/// that name, the first name like it that's free.
fn output_path(input: &Path, here: &Path, name: &Path, plain_name: &Path) -> Result<PathBuf> {
    let own = here.join(name);
    if files::same_file(input, &own) || fs::symlink_metadata(&own).is_err() {
        return Ok(own);
    }
    (2..=1000)
        .map(|n| files::with_suffix(&here.join(plain_name), &format!(".{n}.enc")))
        .find(|path| fs::symlink_metadata(path).is_err())
        .ok_or_else(|| Error::File(explain::no_free_name(&own)))
}

/// Decrypts the whole file into locked memory, which is wiped when it's
/// dropped.
fn decrypt_to_memory(
    encrypted: Encrypted,
    key: &[u8; KEY_LEN],
    input: &Path,
    key_file: Option<&Path>,
) -> Result<(Option<Metadata>, Zeroizing<Vec<u8>>)> {
    let Encrypted { mut source, start, version, len: checked } = encrypted;
    if version != stream::VERSION {
        return decrypt::whole(key, input, key_file);
    }
    let header: [u8; stream::HEADER_LEN] = start[..].try_into().expect("a version 3 file this long has a whole header");
    let read_error = |e| Error::File(explain::file(Action::Read, input, &e));
    // Its size was checked against the memory there is to lock.
    let len = source.metadata().map_err(read_error)?.len();
    if len != checked {
        return Err(Error::File(explain::changed_while_reading(input)));
    }
    let body_len = len.saturating_sub(stream::HEADER_LEN as u64);
    // Allocated at the most the contents could be, so it never grows and
    // leaves copies behind.
    let mut contents = files::secret_buffer(body_len)?;
    let mut rest = &mut contents[..];
    let opened = stream::decrypt(key, &header, &mut source, body_len, &mut rest, &mut |_| {})
        .map_err(|e| explain::stream_failure(e, input, input, key_file))?;
    contents.truncate(opened.len as usize);
    Ok((Some(opened.metadata), contents))
}

/// Encrypts the viewed file again as `output`: with the same key, or else one
/// chosen from scratch, as encrypt asks for it. The new file is read back
/// from the disk before it replaces anything, which can only be the file
/// viewed.
fn reencrypt(
    viewed: Viewed,
    key: SecretKey,
    key_file: Option<PathBuf>,
    same_key: bool,
    output: &Path,
    options: &Options,
) -> Result<()> {
    // The folder this writes in (for the file, a new key and a saved summary)
    // has its modified time set back when this returns.
    let _dir_times = timestamps::DirTimes::capture([files::parent_dir(output)]);
    let mut new_key_file = UnusedKeyFile::default();
    let (key, source, history) = if same_key {
        let source = match &key_file {
            Some(path) => KeySource::FromFile { path: path.clone() },
            None => KeySource::Entered,
        };
        (key, source, viewed.history)
    } else {
        drop(key);
        let (key, source) = keys::establish(&viewed.plain_name, &mut new_key_file, &Options::default())?;
        let history = history::clean(Some(&key));
        (key, source, history)
    };

    let replaces_viewed = files::same_file(&viewed.input, output);
    let metadata = viewed.metadata.unwrap_or_default();
    let meta_len = metadata.encoded_len();
    let mut encoded = files::secret_buffer(meta_len as u64)?;
    metadata.encode(&mut encoded);
    let len = viewed.contents.len() as u64;
    let mut out = PartFile::create(output, replaces_viewed)?;
    let sealed = stream::encrypt(&key, &encoded, &mut &viewed.contents[..], len, &mut out, &mut |_| {})
        .map_err(|e| explain::stream_failure(e, &viewed.input, output, None))?;
    drop(encoded);
    if let Err(e) = encrypt::verify(&key, out.flushed()?, len, &sealed.hash) {
        return Err(match e {
            Error::Interrupted => e,
            e => Error::File(format!(
                "{e}\nThe new encrypted file didn't read back from disk as it was written, so it was \
                 removed and nothing was replaced.\n{}",
                explain::DISK_TROUBLE
            )),
        });
    }
    drop(key);
    // Last chance to back out: past this point a file it replaces is gone.
    if protect::stop_requested() {
        return Err(Error::Interrupted);
    }
    let replaced = out.finish()?;
    new_key_file.keep();

    eprintln!("Re-encrypted file saved as: {}", safe_path(output));
    if !replaces_viewed {
        let still = if same_key { "" } else { ", and still opens with the old key" };
        eprintln!(
            "The file you viewed, {}, is unchanged{still}. Delete it if you no longer need it.",
            safe_path(&viewed.input)
        );
    } else if let (false, Some(old)) = (same_key, &key_file) {
        eprintln!("The old key, {}, no longer opens it.", safe_path(old));
    }
    if options.quiet {
        return Ok(());
    }

    let overhead = stream::HEADER_LEN + meta_len + sealed.chunks as usize * stream::TAG_LEN;
    let stored = match metadata.summary() {
        summary if summary.is_empty() => "none: the file viewed had none stored".to_string(),
        summary => format!("stored encrypted: {summary}"),
    };
    let mut rows = vec![("Cipher", "AES-256-GCM (authenticated encryption)".to_string())];
    rows.extend(encrypt::key_rows(&source));
    rows.extend([
        ("File key", "derived with HKDF-SHA256 from the key and a new random 256-bit salt".into()),
        ("Viewed", format!("{}  {}", safe_path(&viewed.input), viewed.shown)),
        (
            "Output",
            format!(
                "{}  {}{}",
                safe_path(output),
                fmt_size(len + overhead as u64),
                decrypt::replaced_note(replaced)
            ),
        ),
        ("Metadata", stored),
        ("Integrity", "verified: re-read from disk, decrypted, SHA-256 matches what was viewed".into()),
        ("Key and data", protect::memory_status().into()),
        ("Shell history", history),
    ]);
    let mut secrets = vec![safe_path(&viewed.input), safe_path(output)];
    secrets.extend(encrypt::key_path(&source).map(safe_path));
    report::show("RE-ENCRYPTION SUCCESSFUL", &rows, "encryption-summary", true, &secrets)
}
