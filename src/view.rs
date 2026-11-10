//! The view command: an encrypted file decrypted into locked memory and shown
//! on a screen of its own until Enter, then erased from the screen. The user
//! then keeps its key, which leaves the file as it was, or encrypts it again
//! where it is with a new key or passphrase. The decrypted file is only ever
//! in locked memory and on the terminal: if anything the plaintext would go
//! in can't be locked, the run stops before putting it there. The encrypted
//! file is only replaced once the new one has been read back and checked.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::cli::Options;
use crate::decrypt::{self, Encrypted, Unlocked};
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::{self, PartFile};
use crate::keys::{self, UnusedKeyFile};
use crate::meta::Metadata;
use crate::report::{self, fmt_size};
use crate::term::{self, choose, confirm, safe_path};
use crate::{encrypt, history, pager, protect, recording, session, stream};

/// Locked memory needed beyond the file itself: the stack, the chunk being
/// decrypted, the screen being drawn, the key and the answers typed.
const LOCK_MARGIN: u64 = 1 << 20;

/// A file decrypted and shown, to be encrypted again with a new key.
struct Viewed {
    /// The encrypted file it came from, which the new one replaces.
    input: PathBuf,
    /// Its name decrypted, which a new key file is named after.
    plain_name: PathBuf,
    contents: Zeroizing<Vec<u8>>,
    metadata: Option<Metadata>,
    /// How it was shown, for the report.
    shown: String,
}

pub fn command(file: Option<&str>, options: &Options) -> Result<()> {
    // Someone at the keyboard says when they're done and whether to keep the
    // key, and the file needs a terminal it can be erased from. Both are
    // checked before a key is asked for.
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

    // From here on, if anything the plaintext would go in can't be locked,
    // the run stops before putting it there. What hashing, the cipher and
    // formatting leave on the stack is locked too, and so is the key.
    protect::require_locking();
    protect::lock_stack();
    protect::check_locked()?;
    session::remember(format!("File to view: {}", safe_path(&input)));
    let name = PathBuf::from(input.file_name().unwrap_or_default());
    let plain_name = files::decrypted_path(&name);

    let unlocked = decrypt::key(options, "encryptor view", &plain_name, &encrypted)?;
    // Looked for before the file is decrypted, as looking can start other
    // programs, so none is started while the plaintext is in memory.
    let recorders = recording::scan();
    let (metadata, contents) = decrypt_to_memory(encrypted, &unlocked, &input)?;

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

    // Encrypted again with the same key, it would open just as it does now,
    // so it's only rewritten for a new one.
    let same = match (&unlocked.key_file, unlocked.passphrase) {
        (_, true) => "the same passphrase".to_string(),
        (Some(path), false) => format!("the same key, from {}", safe_path(path)),
        (None, false) => "the same key you entered".into(),
    };
    eprintln!();
    if let Err(e) = files::can_create(&input) {
        eprintln!(
            "{} is left as it was, still opening with {same}: it can't be encrypted with a new key where it \
             is, as {}.",
            safe_path(&input),
            explain::cause(Action::Create, &input, &e)
        );
        return Ok(());
    }
    eprintln!("Keep its key, or encrypt it again with a new one:");
    eprintln!("  s  keep {same}, and leave the file as it was");
    eprintln!("  n  a new key or passphrase, replacing {}", safe_path(&input));
    if choose("Same key or a new one?", &["same", "new"])? == "same" {
        eprintln!("Left as it was: {} still opens with {same}.", safe_path(&input));
        return Ok(());
    }
    let old = match (&unlocked.key_file, unlocked.passphrase) {
        (_, true) => "The old passphrase".to_string(),
        (Some(path), false) => format!("The old key file, {},", safe_path(path)),
        (None, false) => "The old key".into(),
    };
    drop(unlocked);
    reencrypt(Viewed { input, plain_name, contents, metadata, shown }, &old, options)
}

/// Decrypts the whole file into locked memory, which is wiped when it's
/// dropped.
fn decrypt_to_memory(
    encrypted: Encrypted,
    unlocked: &Unlocked,
    input: &Path,
) -> Result<(Option<Metadata>, Zeroizing<Vec<u8>>)> {
    let Encrypted { mut source, start, version, len: checked } = encrypted;
    if version < stream::VERSION {
        return decrypt::whole(&unlocked.key, input, unlocked.key_file.as_deref());
    }
    let read_error = |e| Error::File(explain::file(Action::Read, input, &e));
    // Its size was checked against the memory there is to lock.
    let len = source.metadata().map_err(read_error)?.len();
    if len != checked {
        return Err(Error::File(explain::changed_while_reading(input)));
    }
    let body_len = len.saturating_sub(start.len() as u64);
    // Allocated at the most the contents could be, so it never grows and
    // leaves copies behind.
    let mut contents = files::secret_buffer(body_len)?;
    let mut rest = &mut contents[..];
    let opened = stream::decrypt(&unlocked.key, &start, &mut source, body_len, &mut rest, &mut |_| {})
        .map_err(|e| decrypt::failure(e, input, input, unlocked))?;
    contents.truncate(opened.len as usize);
    Ok((Some(opened.metadata), contents))
}

/// Encrypts the viewed file again where it is, with a new key or passphrase
/// chosen from scratch, as encrypt asks for one. The new file is read back
/// from the disk before it replaces the old. `old` names what no longer opens
/// it, for the message afterwards.
fn reencrypt(viewed: Viewed, old: &str, options: &Options) -> Result<()> {
    let input = &viewed.input;
    let mut new_key_file = UnusedKeyFile::default();
    let (secret, source) = keys::establish(&viewed.plain_name, &mut new_key_file, &Options::default())?;
    let history = history::clean(secret.held());
    let header = stream::header(secret.kdf()).map_err(|e| explain::stream_failure(e, input, input, None))?;
    let key = secret.key_for(&header)?;

    let metadata = viewed.metadata.unwrap_or_default();
    let meta_len = metadata.encoded_len();
    let mut encoded = files::secret_buffer(meta_len as u64)?;
    metadata.encode(&mut encoded);
    let len = viewed.contents.len() as u64;
    let mut out = PartFile::create(input, true)?;
    let sealed = stream::encrypt(&key, &header, &encoded, &mut &viewed.contents[..], len, &mut out, &mut |_| {})
        .map_err(|e| explain::stream_failure(e, input, input, None))?;
    drop(encoded);
    if let Err(e) = encrypt::verify(&key, out.flushed()?, len, &sealed.hash) {
        return Err(match e {
            Error::Interrupted => e,
            e => Error::File(format!(
                "{e}\nThe new encrypted file didn't read back from disk as it was written, so it was \
                 removed, and {} is as it was.\n{}",
                safe_path(input),
                explain::DISK_TROUBLE
            )),
        });
    }
    drop(key);
    // Last chance to back out: past this point the old file is gone.
    if protect::stop_requested() {
        return Err(Error::Interrupted);
    }
    let replaced = out.finish()?;
    new_key_file.keep();

    eprintln!("Encrypted again with the new key: {}", safe_path(input));
    eprintln!("{old} no longer opens it.");
    if options.quiet {
        return Ok(());
    }

    let overhead = header.len() + meta_len + sealed.chunks as usize * stream::TAG_LEN;
    let stored = match metadata.summary() {
        summary if summary.is_empty() => "none: the file viewed had none stored".to_string(),
        summary => format!("stored encrypted: {summary}"),
    };
    let mut rows = vec![("Cipher", "AES-256-GCM (authenticated encryption)".to_string())];
    rows.extend(encrypt::key_rows(&source));
    rows.extend([
        ("File key", "derived with HKDF-SHA256 from the key and a new random 256-bit salt".into()),
        ("Viewed", viewed.shown),
        (
            "Output",
            format!(
                "{}  {}{}",
                safe_path(input),
                fmt_size(len + overhead as u64),
                decrypt::replaced_note(replaced)
            ),
        ),
        ("Metadata", stored),
        ("Integrity", "verified: re-read from disk, decrypted, SHA-256 matches what was viewed".into()),
        ("Key and data", protect::memory_status().into()),
        ("Shell history", history),
    ]);
    report::show("RE-ENCRYPTION SUCCESSFUL", &rows, "encryption-summary", true)
}
