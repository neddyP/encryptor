//! aes256: interactive AES-256-GCM file encryption and decryption.
//!
//! Encrypted file layout (sizes in bytes):
//!
//! ```text
//! +--------------+-------------+------------+----------------+----------+
//! | magic "AGCM" | version (2) | nonce (12) | ciphertext (n) | tag (16) |
//! +--------------+-------------+------------+----------------+----------+
//! ```
//!
//! The 17-byte header is passed to GCM as associated data, so changing any
//! byte of the header, ciphertext or tag makes decryption fail. From version 2
//! the plaintext starts with the original file's metadata (see `meta`), so it
//! is encrypted too; version 1 files hold only the contents.

mod explain;
mod meta;
mod protect;
mod recording;
mod term;
mod wipe;

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use explain::Action;
use meta::Metadata;
use term::{Shown, safe, safe_path};

const MAGIC: &[u8; 4] = b"AGCM";
/// The format version written. Version 1, without metadata, is still read.
const VERSION: u8 = 2;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const NONCE_START: usize = MAGIC.len() + 1;
const HEADER_LEN: usize = NONCE_START + NONCE_LEN;
const ENC_EXT: &str = "enc";
const AUTH_FAILED: &str =
    "authentication failed: wrong key, or the file is corrupted or has been tampered with.";

const USAGE: &str = "\
aes256 - encrypt and decrypt files with AES-256-GCM

USAGE:
    encrypt [FILE]    encrypt FILE to FILE.enc, then delete FILE
    decrypt [FILE]    decrypt FILE.enc back to FILE
    aes256            choose interactively

`encrypt` and `decrypt` are links to aes256; `aes256 encrypt [FILE]` and
`aes256 decrypt [FILE]` do the same thing.

Anything not given on the command line is asked for. When asked for a key,
enter 64 hex characters or the path to a 32-byte key file.

To encrypt a folder or several files, zip them into one file first:
    zip -r photos.zip photos
";

/// Key bytes live on the heap, locked in RAM, so moving the handle never
/// copies the key and it is never swapped out. They are zeroed when dropped.
type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

type Result<T> = std::result::Result<T, String>;

enum KeySource {
    Generated { saved_to: Option<PathBuf>, printed: Printed },
    Entered { history: String },
}

/// Whether a generated key was printed, and whether anything kept a copy.
#[derive(PartialEq)]
enum Printed {
    No,
    /// Shown and erased, with nothing found recording the session.
    Erased,
    /// Shown while the named programs were recording or sharing the session.
    Captured(String),
}

/// Shreds a freshly saved key file unless encryption completes, including
/// when the user stops part way: a key that encrypted nothing shouldn't be
/// left on disk.
struct UnusedKeyFile(Option<PathBuf>);

impl UnusedKeyFile {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for UnusedKeyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            if wipe::shred(path).is_ok() {
                println!("Shredded unused key file {}", safe_path(path));
            }
        }
    }
}

fn main() -> ExitCode {
    protect::harden_process();

    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let Ok(mut args) = args.map(OsString::into_string).collect::<std::result::Result<Vec<_>, _>>() else {
        eprintln!("\nerror: a name on the command line isn't valid UTF-8 text, which this tool can't read.");
        eprintln!("Rename the file using ordinary letters and numbers, then try again.");
        return ExitCode::FAILURE;
    };

    // Started through the `encrypt` or `decrypt` link: the name is the command.
    let name = Path::new(&program).file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if matches!(name, "encrypt" | "decrypt") {
        args.insert(0, name.to_owned());
    }

    let result = run(&args);
    protect::scrub_stack();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e == protect::INTERRUPTED => {
            eprintln!("\ninterrupted; nothing was left behind");
            ExitCode::from(130)
        }
        Err(e) => {
            eprintln!("\nerror: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "-h" || a == "--help") || args.first().is_some_and(|a| a == "help") {
        print!("{USAGE}");
        return Ok(());
    }
    if args.len() > 2 {
        return Err(match args[0].as_str() {
            "encrypt" | "enc" | "e" => explain::zip_instead(&args[1..]),
            "decrypt" | "dec" | "d" => explain::decrypt_one_at_a_time(&args[1..]),
            other => explain::unknown_command(other, USAGE),
        });
    }
    let file = args.get(1).map(String::as_str);
    match args.first().map(String::as_str) {
        Some("encrypt" | "enc" | "e") => encrypt_command(file),
        Some("decrypt" | "dec" | "d") => decrypt_command(file),
        Some(other) => Err(explain::unknown_command(other, USAGE)),
        None => match choose("Encrypt or decrypt?", &["encrypt", "decrypt"])? {
            "encrypt" => encrypt_command(None),
            _ => decrypt_command(None),
        },
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn encrypt_command(file: Option<&str>) -> Result<()> {
    let input = file_path("encrypt", file)?;
    input_len("encrypt", &input)?;
    let output = with_suffix(&input, &format!(".{ENC_EXT}"));
    if output.exists() {
        return Err(explain::output_exists(&output));
    }
    // Problems found now save asking for a key that can't be used.
    open_no_follow(&input).map_err(|e| explain::file(Action::Read, &input, &e))?;
    check_writable(&output)?;

    let mut key_file = UnusedKeyFile(None);
    let (key, source) = establish_key(&input, &mut key_file)?;

    if !confirm("Encrypt using AES-256-GCM?")? {
        println!("Cancelled; nothing was encrypted.");
        return Ok(());
    }

    let started = Instant::now();
    let read_error = |e| explain::file(Action::Read, &input, &e);
    let mut original = wipe::Original::open(&input).map_err(read_error)?;
    let len = original.len().map_err(read_error)?;
    // Captured before reading, which can update the access time.
    let metadata = Metadata::capture(original.file()).map_err(read_error)?;
    let meta_len = metadata.encoded_len();
    if meta_len as u64 + len > aes_gcm::P_MAX {
        return Err(explain::too_large(&input, len));
    }
    let mut data = secret_buffer(meta_len as u64 + len)?;
    metadata.encode(&mut data[..meta_len]);
    original.read_exact(&mut data[meta_len..]).map_err(read_error)?;
    let plain_len = data.len() - meta_len;
    let plain_hash = sha256(&data[meta_len..]);

    let (header, tag) = seal(&key, &mut data)?;
    write_file(&output, &[&header, &data, &tag], false)?;
    drop(data);

    // Prove the file on disk decrypts back to exactly what was read before the
    // original is touched.
    if let Err(e) = verify_encrypted(&key, &output, plain_len, &plain_hash) {
        let _ = wipe::shred(&output);
        return Err(format!(
            "{e}\nThe encrypted file didn't read back from disk as it was written, so it was removed \
             and the original left untouched.\n{}",
            explain::DISK_TROUBLE
        ));
    }
    drop(key);

    // Last chance to back out: past this point the original is destroyed.
    if protect::stop_requested() {
        let _ = wipe::shred(&output);
        return Err(protect::INTERRUPTED.into());
    }
    key_file.keep();
    let original_status = original.destroy(&input);
    let elapsed = started.elapsed();

    let mut rows = vec![("Cipher", "AES-256-GCM (authenticated encryption)".to_string())];
    match &source {
        KeySource::Generated { saved_to, printed } => {
            rows.push(("Key", "256-bit, generated by the OS CSPRNG".into()));
            let storage = match (saved_to, printed) {
                (Some(path), Printed::No) => {
                    format!("saved to {} (owner read/write only)", safe_path(path))
                }
                (Some(path), Printed::Erased) => format!(
                    "saved to {} (owner read/write only); also shown once on screen",
                    safe_path(path)
                ),
                (Some(path), Printed::Captured(by)) => format!(
                    "saved to {} (owner read/write only); also shown on screen and captured \
                     by {by}: anyone with that copy can decrypt the file",
                    safe_path(path)
                ),
                (None, Printed::Captured(by)) => format!(
                    "shown on screen and captured by {by}: anyone with that copy can decrypt \
                     the file; not saved"
                ),
                (None, _) => "shown once on screen, then erased; not saved".into(),
            };
            rows.push(("Key storage", storage));
        }
        KeySource::Entered { .. } => {
            rows.push(("Key", "256-bit, entered by you".into()));
            rows.push(("Key storage", "not stored by this tool".into()));
        }
    }
    rows.extend([
        ("Nonce", format!("{}-bit, random", NONCE_LEN * 8)),
        ("Auth tag", format!("{}-bit", TAG_LEN * 8)),
        ("Input", format!("{}  {}", safe_path(&input), fmt_size(plain_len))),
        (
            "Output",
            format!(
                "{}  {}",
                safe_path(&output),
                fmt_size(HEADER_LEN + meta_len + plain_len + TAG_LEN)
            ),
        ),
        (
            "Overhead",
            format!(
                "{} bytes ({HEADER_LEN} header + {meta_len} metadata + {TAG_LEN} tag)",
                HEADER_LEN + meta_len + TAG_LEN
            ),
        ),
        ("Metadata", format!("stored encrypted: {}", metadata.summary())),
        ("Integrity", "verified: re-read from disk, decrypted, SHA-256 matches original".into()),
        ("Original", original_status),
        ("Key and data", protect::memory_status().into()),
    ]);
    if let KeySource::Entered { history } = source {
        rows.push(("Shell history", history));
    }
    rows.push(("Time", format!("{elapsed:.2?}")));
    print_report("ENCRYPTION SUCCESSFUL", &rows);
    Ok(())
}

fn decrypt_command(file: Option<&str>) -> Result<()> {
    let input = file_path("decrypt", file)?;
    let input_len = input_len("decrypt", &input)?;

    // Reject files this tool didn't produce before asking for the key, saying
    // what they are instead where that can be told.
    let mut start = Vec::with_capacity(HEADER_LEN);
    open_no_follow(&input)
        .and_then(|file| file.take(HEADER_LEN as u64).read_to_end(&mut start))
        .map_err(|e| explain::file(Action::Read, &input, &e))?;
    if !start.starts_with(MAGIC) {
        return Err(explain::not_encrypted(&input, &start));
    }
    if input_len < (HEADER_LEN + TAG_LEN) as u64 {
        return Err(explain::too_short(&input, input_len));
    }
    check_header(&start)?;
    let output = decrypted_path(&input);
    check_writable(&output)?;

    let plain_name = output.file_name().unwrap_or_default().to_string_lossy();
    let give_up = format!(
        "no valid key after 3 attempts.\nRun decrypt again with this file's key: the 64 characters \
         printed when it was encrypted, or its key file, usually {}.key.",
        safe(&plain_name)
    );
    let (key, key_file) = prompt_key(false, &give_up)?;
    let history = scrub_history(&key);

    if !confirm("Decrypt using AES-256-GCM?")? {
        println!("Cancelled; nothing was decrypted.");
        return Ok(());
    }
    let replace = output.exists();
    if replace && !confirm(&format!("{} already exists. Overwrite it?", safe_path(&output)))? {
        println!("Cancelled; nothing was written.");
        return Ok(());
    }

    let started = Instant::now();
    let (metadata, plain) = open(&key, read_file(&input)?).map_err(|e| match e.as_str() {
        AUTH_FAILED => explain::wrong_key(&input, key_file.as_deref()),
        _ => e,
    })?;
    drop(key);
    let plain_len = plain.len();
    let plain_hash = sha256(&plain);

    write_file(&output, &[&plain], replace)?;
    drop(plain);

    if *sha256_file(&output)? != *plain_hash {
        let _ = wipe::shred(&output);
        return Err(format!(
            "{} didn't read back from disk as it was written, so it was removed. The encrypted \
             file is untouched.\n{}",
            safe_path(&output),
            explain::DISK_TROUBLE
        ));
    }
    if protect::stop_requested() {
        let _ = wipe::shred(&output);
        return Err(protect::INTERRUPTED.into());
    }
    // Only now, since the original permissions may not let the file be read
    // back or shredded.
    let metadata_status = match metadata {
        Some(metadata) => match open_no_follow(&output) {
            Ok(file) => metadata.restore(&file),
            Err(e) => format!("not restored: {}", explain::cause(Action::Read, &output, &e)),
        },
        None => "none stored (encrypted by a version before 2.0)".into(),
    };
    let elapsed = started.elapsed();

    print_report(
        "DECRYPTION SUCCESSFUL",
        &[
            ("Cipher", "AES-256-GCM (authenticated encryption)".into()),
            ("Key", "256-bit".into()),
            ("Auth tag", format!("{}-bit, valid: file is authentic and uncorrupted", TAG_LEN * 8)),
            ("Input", format!("{}  {} (kept)", safe_path(&input), fmt_size(input_len as usize))),
            ("Output", format!("{}  {}", safe_path(&output), fmt_size(plain_len))),
            ("Integrity", "verified: re-read from disk, SHA-256 matches decrypted data".into()),
            ("Metadata", metadata_status),
            ("Key and data", protect::memory_status().into()),
            ("Shell history", history),
            ("Time", format!("{elapsed:.2?}")),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

fn establish_key(input: &Path, key_file: &mut UnusedKeyFile) -> Result<(SecretKey, KeySource)> {
    if !confirm("Generate a random 256-bit key?")? {
        let give_up = "no valid key after 3 attempts.\nRun encrypt again and answer y to have a random \
                       key generated, or enter a key of 64 characters, 0-9 and a-f.";
        let (key, _) = prompt_key(true, give_up)?;
        let history = scrub_history(&key);
        return Ok((key, KeySource::Entered { history }));
    }

    let key = generate_key()?;
    println!("Key generated (not displayed).");

    let mut saved_to = None;
    if confirm("Save symmetric encryption key as a file in your current directory?")? {
        saved_to = Some(save_key(&key, input, key_file)?);
    }
    let mut printed = if confirm("Print the key?")? { print_key(&key)? } else { Printed::No };

    // A key that is neither saved nor printed is gone once the program exits,
    // and the file with it, so one of the two is required.
    if saved_to.is_none() && printed == Printed::No {
        println!();
        println!("WARNING: the key has been neither saved nor printed. It exists only in");
        println!("this program's memory, so the encrypted file could never be decrypted.");
        loop {
            if choose("Print or save the key?", &["print", "save"])? == "save" {
                saved_to = Some(save_key(&key, input, key_file)?);
                break;
            }
            printed = print_key(&key)?;
            if printed != Printed::No {
                break;
            }
        }
    }
    Ok((key, KeySource::Generated { saved_to, printed }))
}

/// Saves the key in the working directory, tells the user where, and hands
/// the file to `key_file` to shred if encryption doesn't complete.
fn save_key(key: &[u8; KEY_LEN], input: &Path, key_file: &mut UnusedKeyFile) -> Result<PathBuf> {
    let path = write_key_file(key, input)?;
    key_file.0 = Some(path.clone());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    println!("Key saved as: {}", safe(&name));
    println!("Keep this file safe: anyone who has it can decrypt the file, and");
    println!("without the key the file cannot be decrypted.");
    Ok(path)
}

/// Shows the key on the terminal and erases it afterwards, or explains why it
/// can't be shown here. If anything is recording the session, says what and
/// asks first.
fn print_key(key: &[u8; KEY_LEN]) -> Result<Printed> {
    let recorders = recording::scan();
    let captured_by = (!recorders.is_empty()).then(|| recording::names(&recorders));
    if let Some(by) = &captured_by {
        println!();
        println!("WARNING: something is recording or sharing this terminal session:");
        for recorder in &recorders {
            print!("{recorder}");
        }
        if !confirm(&format!(
            "Printing the key would save it to {by} compromising your encryption, \
             do you still wish to print your decryption key?"
        ))? {
            println!("Key not printed.");
            return Ok(Printed::No);
        }
    }
    match term::show_key(key)? {
        Shown::Yes => match captured_by {
            Some(by) => {
                println!("Key shown, then erased from the screen, but {by} captured it.");
                Ok(Printed::Captured(by))
            }
            None => {
                println!("Key shown, then erased from the screen.");
                Ok(Printed::Erased)
            }
        },
        Shown::Unavailable(reason) => {
            println!("  The key can't be printed here: {reason}. Save it to a file instead.");
            Ok(Printed::No)
        }
    }
}

/// Allocates a key buffer that is locked in RAM and zeroed when dropped.
fn new_key() -> SecretKey {
    let key: SecretKey = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    protect::lock(key.as_ptr(), KEY_LEN);
    key
}

fn generate_key() -> Result<SecretKey> {
    let mut key = new_key();
    getrandom::fill(&mut key[..]).map_err(random_failed)?;
    Ok(key)
}

fn random_failed(e: getrandom::Error) -> String {
    format!(
        "the operating system's random number generator failed: {e}.\nNothing was encrypted. \
         Try again; if it keeps failing, restart the computer."
    )
}

/// Writes the raw key to `<input name>.key` in the working directory, adding a
/// number if that name is taken. Only the owner can read the file.
fn write_key_file(key: &[u8; KEY_LEN], input: &Path) -> Result<PathBuf> {
    let base = input
        .file_name()
        .map_or_else(|| "aes256".into(), |n| n.to_string_lossy().into_owned());
    let dir = std::env::current_dir().map_err(|e| explain::no_working_folder(&e))?;

    for n in 1..=1000 {
        let name = if n == 1 { format!("{base}.key") } else { format!("{base}.{n}.key") };
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(key).and_then(|()| file.sync_all()) {
                    let _ = wipe::shred(&path);
                    return Err(explain::file(Action::Write, &path, &e));
                }
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(explain::file(Action::Create, &path, &e)),
        }
    }
    Err(format!(
        "there are already 1000 key files for {} in {}.\nDelete the ones you no longer need, then try again.",
        safe(&base),
        safe_path(&dir)
    ))
}

/// Asks for a key, allowing three attempts, and returns it with the key file it
/// came from, if any. With `confirm_typed`, a hex key has to be entered twice:
/// the input is hidden, and encrypting with a mistyped key would make the file
/// unrecoverable. `give_up` is the error after three failed attempts.
fn prompt_key(confirm_typed: bool, give_up: &str) -> Result<(SecretKey, Option<PathBuf>)> {
    for _ in 0..3 {
        let input = term::read_secret("Enter key (64 hex characters, or path to a key file): ")?;
        let (key, key_file) = match parse_key(&input) {
            Ok(parsed) => parsed,
            Err(e) => {
                println!("  {e}");
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
        if parse_key(&again).is_ok_and(|(k, _)| *k == *key) {
            return Ok((key, key_file));
        }
        println!("  The two keys didn't match. Enter the same key both times; pasting it avoids typos.");
    }
    Err(give_up.into())
}

/// Accepts 64 hex characters or the path to a 32-byte binary key file, and
/// returns the key with the key file's path, if it came from one. Error
/// messages never echo the input unless it is evidently a path, since it may
/// be a mistyped key, and the path built from it is wiped too.
fn parse_key(input: &str) -> Result<(SecretKey, Option<PathBuf>)> {
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
    let path = Path::new(OsStr::from_bytes(&path_bytes));
    let mut file = File::open(path).map_err(|e| explain::not_a_key(input, path, &e))?;
    let meta = file.metadata().map_err(|e| explain::file(Action::Read, path, &e))?;
    if meta.is_dir() {
        return Err(explain::key_file_folder(path));
    }
    if meta.len() != KEY_LEN as u64 {
        return Err(explain::key_file_size(path, meta.len()));
    }
    file.read_exact(&mut key[..]).map_err(|e| explain::file(Action::Read, path, &e))?;
    Ok((key, Some(path.to_path_buf())))
}

/// Redacts every copy of the key from shell history files, in case it was
/// ever typed or pasted into a command, and describes the result.
fn scrub_history(key: &[u8; KEY_LEN]) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let shown = |path: &Path| match home.as_deref().and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", safe_path(rest)),
        None => safe_path(path),
    };
    let mut redacted = Vec::new();
    let mut unreadable = Vec::new();
    for path in wipe::history_files() {
        match wipe::redact_key(&path, key) {
            Ok(0) => {}
            Ok(n) => redacted.push(format!("{n} in {}", shown(&path))),
            Err(e) => unreadable.push(format!("{} ({e})", shown(&path))),
        }
    }
    let mut status = if redacted.is_empty() {
        "key not found in shell history".to_string()
    } else {
        format!("key redacted ({})", redacted.join(", "))
    };
    if !unreadable.is_empty() {
        status.push_str(&format!("; could not check {}", unreadable.join(", ")));
    }
    status
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

/// Encrypts `data` in place under a fresh random nonce and returns the header
/// and authentication tag that surround the ciphertext on disk.
fn seal(key: &[u8; KEY_LEN], data: &mut [u8]) -> Result<([u8; HEADER_LEN], [u8; TAG_LEN])> {
    let mut header = [0u8; HEADER_LEN];
    header[..NONCE_START - 1].copy_from_slice(MAGIC);
    header[NONCE_START - 1] = VERSION;
    getrandom::fill(&mut header[NONCE_START..]).map_err(random_failed)?;

    let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).expect("nonce is 12 bytes");
    let tag = Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce, &header, data.into())
        .map_err(|_| "encryption failed".to_string())?;
    Ok((header, tag.into()))
}

/// Authenticates and decrypts a complete encrypted file image in place and
/// returns the stored metadata, if the version has any, and the contents.
/// Fails if the key is wrong or any byte of the header, ciphertext or tag has
/// changed.
fn open(key: &[u8; KEY_LEN], mut blob: Zeroizing<Vec<u8>>) -> Result<(Option<Metadata>, Zeroizing<Vec<u8>>)> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err("file is too short to be an encrypted file".into());
    }
    let version = check_header(&blob)?;

    let body_len = blob.len() - HEADER_LEN - TAG_LEN;
    let (header, rest) = blob.split_at_mut(HEADER_LEN);
    let (body, tag) = rest.split_at_mut(body_len);
    let header = &*header;
    let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).expect("nonce is 12 bytes");
    let tag = <&Tag<Aes256Gcm>>::try_from(&*tag).expect("tag is 16 bytes");

    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(nonce, header, body.into(), tag)
        .map_err(|_| AUTH_FAILED.to_string())?;

    let (metadata, skip) = match version {
        1 => (None, 0),
        _ => {
            let (metadata, len) = Metadata::parse(&blob[HEADER_LEN..HEADER_LEN + body_len])?;
            (Some(metadata), len)
        }
    };
    blob.copy_within(HEADER_LEN + skip..HEADER_LEN + body_len, 0);
    blob.truncate(body_len - skip);
    Ok((metadata, blob))
}

/// Checks the magic bytes and returns the format version.
fn check_header(bytes: &[u8]) -> Result<u8> {
    if bytes.len() < HEADER_LEN || bytes[..MAGIC.len()] != MAGIC[..] {
        return Err("not a file encrypted by this tool (missing AGCM header)".into());
    }
    match bytes[NONCE_START - 1] {
        v @ 1..=VERSION => Ok(v),
        v => Err(explain::unsupported_version(v)),
    }
}

/// Checks that the file on disk decrypts back to the original contents, and
/// that its metadata reads back too.
fn verify_encrypted(key: &[u8; KEY_LEN], path: &Path, len: usize, hash: &[u8; 32]) -> Result<()> {
    let (_, plain) = open(key, read_file(path)?).map_err(|e| format!("verification failed: {e}"))?;
    if plain.len() != len || *sha256(&plain) != *hash {
        return Err("verification failed: decrypted file does not match the original".into());
    }
    Ok(())
}

fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(data).into())
}

fn sha256_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let read_error = |e| explain::file(Action::Read, path, &e);
    let mut file = open_no_follow(path).map_err(read_error)?;
    let mut buf = secret_buffer(1 << 16)?;
    let mut hasher = Sha256::new();
    loop {
        let n = file.read(&mut buf).map_err(read_error)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Zeroizing::new(hasher.finalize().into()))
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// The size of the file `command` was given, if it's a regular file, or an
/// explanation of why it can't be used.
fn input_len(command: &str, path: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(path).map_err(|e| explain::missing(command, path, &e))?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(explain::symlink(command, path));
    }
    if kind.is_dir() {
        return Err(match command {
            "encrypt" => explain::zip_instead(&[path.to_string_lossy().into_owned()]),
            _ => explain::decrypt_folder(path),
        });
    }
    if !kind.is_file() {
        return Err(explain::special(path, kind));
    }
    Ok(meta.len())
}

/// Fails, explaining why, if `path` couldn't be created in its folder.
fn check_writable(path: &Path) -> Result<()> {
    let folder = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let folder = std::ffi::CString::new(folder.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: access only reads the NUL-terminated path.
    if unsafe { libc::access(folder.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        return Ok(());
    }
    Err(explain::file(Action::Create, path, &io::Error::last_os_error()))
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// A zeroed buffer for plaintext and other secrets: allocated at its final
/// size so it never reallocates and leaves copies behind, locked in RAM when
/// the limit allows, and wiped when dropped.
fn secret_buffer(len: u64) -> Result<Zeroizing<Vec<u8>>> {
    let size = usize::try_from(len).map_err(|_| explain::no_memory(len))?;
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(size).map_err(|_| explain::no_memory(len))?;
    buf.resize(size, 0);
    protect::lock(buf.as_ptr(), size);
    Ok(buf)
}

/// Reads a whole file, refusing symlinks, into a secret buffer.
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let read_error = |e| explain::file(Action::Read, path, &e);
    let mut file = open_no_follow(path).map_err(read_error)?;
    let len = file.metadata().map_err(read_error)?.len();
    let mut buf = secret_buffer(len)?;
    file.read_exact(&mut buf).map_err(read_error)?;
    Ok(buf)
}

/// Writes `parts` to `path` through a temporary file in the same directory, so
/// a crash never leaves a half-written file under the final name. New files
/// are readable by the owner only. A temporary file that can't be finished is
/// shredded, not just deleted, since it may hold plaintext.
fn write_file(path: &Path, parts: &[&[u8]], replace: bool) -> Result<()> {
    if !replace && path.exists() {
        return Err(format!("{} already exists", safe_path(path)));
    }
    let tmp = with_suffix(path, &format!(".{}.part", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| explain::file(Action::Create, path, &e))?;
    let written = parts
        .iter()
        .try_for_each(|part| file.write_all(part))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = wipe::shred(&tmp);
        return Err(explain::file(Action::Write, path, &e));
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn decrypted_path(input: &Path) -> PathBuf {
    if input.extension().is_some_and(|ext| ext == ENC_EXT) {
        input.with_extension("")
    } else {
        with_suffix(input, ".dec")
    }
}

// ---------------------------------------------------------------------------
// Prompts and output
// ---------------------------------------------------------------------------

fn confirm(question: &str) -> Result<bool> {
    Ok(choose(question, &["yes", "no"])? == "yes")
}

/// Asks until the answer is one of `options`, typed in full or as its first
/// letter, and returns the chosen option.
fn choose<'a>(question: &str, options: &[&'a str]) -> Result<&'a str> {
    let letters: Vec<&str> = options.iter().map(|option| &option[..1]).collect();
    let prompt = format!("{question} [{}]: ", letters.join("/"));
    loop {
        let answer = term::read_line(&prompt)?.to_ascii_lowercase();
        let chosen = options
            .iter()
            .copied()
            .find(|option| answer == *option || answer == option[..1]);
        if let Some(option) = chosen {
            return Ok(option);
        }
        println!("  please answer {}", letters.join(" or "));
    }
}

/// The file `command` works on: the one given on the command line, or else
/// one typed at a prompt.
fn file_path(command: &str, arg: Option<&str>) -> Result<PathBuf> {
    match arg {
        Some(arg) => Ok(PathBuf::from(arg)),
        None => {
            let raw = term::read_line(&format!("File to {command}: "))?;
            if raw.is_empty() {
                return Err(explain::no_file_given(command));
            }
            Ok(clean_path(&raw))
        }
    }
}

/// Tidies a typed or dragged-in path: strips surrounding quotes and expands a
/// leading `~/`, which the shell would normally do.
fn clean_path(raw: &str) -> PathBuf {
    let s = raw.trim();
    let s = s
        .strip_prefix('\'')
        .and_then(|t| t.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|t| t.strip_suffix('"')))
        .unwrap_or(s);
    match (s.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(s),
    }
}

fn print_report(title: &str, rows: &[(&str, String)]) {
    let rule = "-".repeat(64);
    println!("\n{rule}\n  {title}\n{rule}");
    for (label, value) in rows {
        println!("  {label:<14} {value}");
    }
    println!("{rule}");
}

fn fmt_size(bytes: usize) -> String {
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = "";
    for u in ["KiB", "MiB", "GiB", "TiB"] {
        value /= 1024.0;
        unit = u;
        if value < 1024.0 {
            break;
        }
    }
    format!("{bytes} bytes ({value:.1} {unit})")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        Box::new(Zeroizing::new([byte; KEY_LEN]))
    }

    fn encrypt_with(key: &[u8; KEY_LEN], metadata: &Metadata, plain: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut data = vec![0; metadata.encoded_len()];
        metadata.encode(&mut data);
        data.extend_from_slice(plain);
        let (header, tag) = seal(key, &mut data).unwrap();
        Zeroizing::new([&header[..], &data, &tag].concat())
    }

    fn encrypt(key: &[u8; KEY_LEN], plain: &[u8]) -> Zeroizing<Vec<u8>> {
        encrypt_with(key, &Metadata::default(), plain)
    }

    #[test]
    fn round_trips_all_sizes() {
        let k = key(7);
        for len in [0, 1, 15, 16, 17, 4096, 100_003] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = encrypt(&k, &plain);
            assert_eq!(blob.len(), HEADER_LEN + 4 + len + TAG_LEN);
            assert_eq!(&open(&k, blob).unwrap().1[..], &plain[..]);
        }
    }

    #[test]
    fn carries_metadata_inside_the_encryption() {
        let path = std::env::temp_dir().join(format!("aes256-carry-{}", std::process::id()));
        fs::write(&path, b"contents").unwrap();
        let metadata = Metadata::capture(&File::open(&path).unwrap()).unwrap();
        fs::remove_file(&path).unwrap();

        let blob = encrypt_with(&key(8), &metadata, b"contents");
        assert!(!blob.windows(8).any(|w| w == b"contents"), "contents visible");
        let (stored, plain) = open(&key(8), blob).unwrap();
        assert_eq!(stored, Some(metadata));
        assert_eq!(&plain[..], b"contents");
    }

    #[test]
    fn opens_version_1_files_without_metadata() {
        let k = key(9);
        let raw: &[u8; KEY_LEN] = &k;
        let mut blob = [&MAGIC[..], &[1], &[7; NONCE_LEN]].concat();
        let mut body = b"made by 0.1".to_vec();
        let nonce = <&Nonce<Aes256Gcm>>::try_from(&blob[NONCE_START..]).unwrap();
        let tag = Aes256Gcm::new(raw.into())
            .encrypt_inout_detached(nonce, &blob, body.as_mut_slice().into())
            .unwrap();
        blob.extend_from_slice(&body);
        blob.extend_from_slice(&tag);

        let (stored, plain) = open(&k, Zeroizing::new(blob)).unwrap();
        assert_eq!(stored, None);
        assert_eq!(&plain[..], b"made by 0.1");
    }

    #[test]
    fn refuses_versions_it_does_not_know() {
        let mut blob = encrypt(&key(1), b"x");
        blob[NONCE_START - 1] = VERSION + 1;
        assert!(open(&key(1), blob).unwrap_err().contains("made by a newer version of encryptor"));
    }

    #[test]
    fn rejects_wrong_key() {
        let blob = encrypt(&key(1), b"secret");
        assert!(open(&key(2), blob).unwrap_err().contains("authentication failed"));
    }

    #[test]
    fn rejects_any_modified_byte() {
        let blob = encrypt(&key(3), b"thirty-two bytes of plaintext!!!");
        for i in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[i] ^= 0x01;
            assert!(open(&key(3), tampered).is_err(), "byte {i} change went unnoticed");
        }
    }

    #[test]
    fn rejects_truncated_file() {
        let blob = encrypt(&key(4), b"hello");
        let short = Zeroizing::new(blob[..blob.len() - 1].to_vec());
        assert!(open(&key(4), short).is_err());
    }

    #[test]
    fn uses_a_fresh_nonce_every_time() {
        let k = key(5);
        assert_ne!(encrypt(&k, b"same input"), encrypt(&k, b"same input"));
    }

    #[test]
    fn parses_hex_keys() {
        let hex = "00112233445566778899aabbccddeeffFFEEDDCCBBAA99887766554433221100";
        let (k, key_file) = parse_key(hex).unwrap();
        assert_eq!((k[0], k[15], k[16], key_file), (0x00, 0xff, 0xff, None));
        assert!(parse_key(&hex[1..]).unwrap_err().contains("That's 1 short"));
        assert!(parse_key("").unwrap_err().starts_with("nothing was entered"));
        assert!(parse_key("not a key").unwrap_err().starts_with("that isn't a key or a key file"));
        // Mistakes are described without repeating the input.
        let spaced = format!("{} {}", &hex[..32], &hex[32..]);
        assert_eq!(parse_key(&spaced).unwrap_err(), "that key has spaces in it. Enter just its 64 characters of 0-9 and a-f.");
        let mut typo = hex.to_string();
        typo.replace_range(9..10, "O");
        let e = parse_key(&typo).unwrap_err();
        assert!(e.contains("character 10 is the letter O") && !e.contains(&typo[..9]), "{e}");
    }

    #[test]
    fn reads_key_files() {
        let dir = std::env::temp_dir().join(format!("aes256-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.key");
        let bad = dir.join("bad.key");
        fs::write(&good, [9u8; KEY_LEN]).unwrap();
        fs::write(&bad, [9u8; KEY_LEN - 1]).unwrap();

        let (k, key_file) = parse_key(good.to_str().unwrap()).unwrap();
        assert_eq!((**k, key_file), ([9u8; KEY_LEN], Some(good.clone())));
        assert!(parse_key(bad.to_str().unwrap()).unwrap_err().contains("key files are exactly 32 bytes"));
        let missing = dir.join("missing.key");
        assert!(parse_key(missing.to_str().unwrap()).unwrap_err().starts_with("there's no key file at"));
        assert!(parse_key(dir.to_str().unwrap()).unwrap_err().contains("is a folder, not a key file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn names_decrypted_files() {
        assert_eq!(decrypted_path(Path::new("a/report.pdf.enc")), Path::new("a/report.pdf"));
        assert_eq!(decrypted_path(Path::new("notes")), Path::new("notes.dec"));
    }
}
