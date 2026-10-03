//! aes256: interactive AES-256-GCM file encryption and decryption.
//!
//! Encrypted file layout (sizes in bytes):
//!
//! ```text
//! +--------------+-------------+------------+----------------+----------+
//! | magic "AGCM" | version (1) | nonce (12) | ciphertext (n) | tag (16) |
//! +--------------+-------------+------------+----------------+----------+
//! ```
//!
//! The 17-byte header is passed to GCM as associated data, so changing any
//! byte of the header, ciphertext or tag makes decryption fail.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"AGCM";
const VERSION: u8 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const NONCE_START: usize = MAGIC.len() + 1;
const HEADER_LEN: usize = NONCE_START + NONCE_LEN;
const ENC_EXT: &str = "enc";

const USAGE: &str = "\
aes256 - encrypt and decrypt files with AES-256-GCM

USAGE:
    aes256 encrypt [FILE]    encrypt FILE to FILE.enc, then delete FILE
    aes256 decrypt [FILE]    decrypt FILE.enc back to FILE
    aes256                   choose interactively

Anything not given on the command line is asked for. When asked for a key,
enter 64 hex characters or the path to a 32-byte key file.
";

/// Key bytes live on the heap so moving the handle never copies the key, and
/// are overwritten with zeros when dropped.
type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

type Result<T> = std::result::Result<T, String>;

enum KeySource {
    Generated { saved_to: Option<PathBuf> },
    Entered,
}

/// Deletes a freshly saved key file unless encryption completes, since a key
/// that encrypted nothing is just clutter.
struct UnusedKeyFile(Option<PathBuf>);

impl UnusedKeyFile {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for UnusedKeyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            if fs::remove_file(path).is_ok() {
                println!("Removed unused key file {}", path.display());
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nerror: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    if args.len() > 2 {
        return Err(format!("too many arguments\n\n{USAGE}"));
    }
    let file = args.get(1).map(String::as_str);
    match args.first().map(String::as_str) {
        Some("encrypt" | "enc" | "e") => encrypt_command(file),
        Some("decrypt" | "dec" | "d") => decrypt_command(file),
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'\n\n{USAGE}")),
        None => loop {
            match ask("Encrypt or decrypt? [e/d]: ")?.to_ascii_lowercase().as_str() {
                "e" | "encrypt" => return encrypt_command(None),
                "d" | "decrypt" => return decrypt_command(None),
                _ => println!("  please answer e or d"),
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn encrypt_command(file: Option<&str>) -> Result<()> {
    let input = file_path(file, "File to encrypt: ")?;
    regular_file_len(&input)?;
    let output = with_suffix(&input, &format!(".{ENC_EXT}"));
    if output.exists() {
        return Err(format!("{} already exists; move it out of the way first", output.display()));
    }

    let (key, source) = establish_key(&input)?;
    let key_file = UnusedKeyFile(match &source {
        KeySource::Generated { saved_to } => saved_to.clone(),
        KeySource::Entered => None,
    });

    if !confirm("Encrypt using AES-256-GCM?")? {
        println!("Cancelled; nothing was encrypted.");
        return Ok(());
    }

    let started = Instant::now();
    let mut data = read_file(&input)?;
    if data.len() as u64 > aes_gcm::P_MAX {
        return Err("file is larger than the 64 GiB AES-GCM limit".into());
    }
    let plain_len = data.len();
    let plain_hash = sha256(&data);

    let (header, tag) = seal(&key, &mut data)?;
    write_file(&output, &[&header, &data, &tag], false)?;
    drop(data);

    // Prove the file on disk decrypts back to exactly what was read before the
    // original is touched.
    if let Err(e) = verify_encrypted(&key, &output, plain_len, &plain_hash) {
        let _ = fs::remove_file(&output);
        return Err(format!("{e}\nremoved {} and left the original untouched", output.display()));
    }
    drop(key);
    key_file.keep();

    let original = shred_and_delete(&input);
    let elapsed = started.elapsed();

    let (key_desc, storage) = match &source {
        KeySource::Generated { saved_to: Some(path) } => (
            "256-bit, generated by the OS CSPRNG",
            format!("saved to {} (owner read/write only)", path.display()),
        ),
        KeySource::Generated { saved_to: None } => {
            ("256-bit, generated by the OS CSPRNG", "printed once, not saved".to_string())
        }
        KeySource::Entered => ("256-bit, entered by you", "not stored by this tool".to_string()),
    };
    print_report(
        "ENCRYPTION SUCCESSFUL",
        &[
            ("Cipher", "AES-256-GCM (authenticated encryption)".into()),
            ("Key", key_desc.into()),
            ("Key storage", storage),
            ("Nonce", format!("{}-bit, random", NONCE_LEN * 8)),
            ("Auth tag", format!("{}-bit", TAG_LEN * 8)),
            ("Input", format!("{}  {}", input.display(), fmt_size(plain_len))),
            (
                "Output",
                format!("{}  {}", output.display(), fmt_size(HEADER_LEN + plain_len + TAG_LEN)),
            ),
            (
                "Overhead",
                format!("{} bytes ({HEADER_LEN} header + {TAG_LEN} tag)", HEADER_LEN + TAG_LEN),
            ),
            ("Integrity", "verified: re-read from disk, decrypted, SHA-256 matches original".into()),
            ("Original", original),
            ("Key in memory", "wiped (zeroized)".into()),
            ("Time", format!("{elapsed:.2?}")),
        ],
    );
    Ok(())
}

fn decrypt_command(file: Option<&str>) -> Result<()> {
    let input = file_path(file, "File to decrypt: ")?;
    let input_len = regular_file_len(&input)?;

    // Reject files this tool didn't produce before asking for the key.
    if input_len < (HEADER_LEN + TAG_LEN) as u64 {
        return Err(format!("{} is too short to be an encrypted file", input.display()));
    }
    let mut header = [0u8; HEADER_LEN];
    File::open(&input)
        .and_then(|mut f| f.read_exact(&mut header))
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    check_header(&header)?;
    let output = decrypted_path(&input);

    let key = prompt_key(false)?;

    if !confirm("Decrypt using AES-256-GCM?")? {
        println!("Cancelled; nothing was decrypted.");
        return Ok(());
    }
    let replace = output.exists();
    if replace && !confirm(&format!("{} already exists. Overwrite it?", output.display()))? {
        println!("Cancelled; nothing was written.");
        return Ok(());
    }

    let started = Instant::now();
    let plain = open(&key, read_file(&input)?)?;
    drop(key);
    let plain_len = plain.len();
    let plain_hash = sha256(&plain);

    write_file(&output, &[&plain], replace)?;
    drop(plain);

    if sha256_file(&output)? != plain_hash {
        let _ = fs::remove_file(&output);
        return Err(format!(
            "{} did not read back correctly from disk and was removed",
            output.display()
        ));
    }
    let elapsed = started.elapsed();

    print_report(
        "DECRYPTION SUCCESSFUL",
        &[
            ("Cipher", "AES-256-GCM (authenticated encryption)".into()),
            ("Key", "256-bit".into()),
            ("Auth tag", format!("{}-bit, valid: file is authentic and uncorrupted", TAG_LEN * 8)),
            ("Input", format!("{}  {} (kept)", input.display(), fmt_size(input_len as usize))),
            ("Output", format!("{}  {}", output.display(), fmt_size(plain_len))),
            ("Integrity", "verified: re-read from disk, SHA-256 matches decrypted data".into()),
            ("Key in memory", "wiped (zeroized)".into()),
            ("Time", format!("{elapsed:.2?}")),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

fn establish_key(input: &Path) -> Result<(SecretKey, KeySource)> {
    if !confirm("Generate a random 256-bit key?")? {
        return Ok((prompt_key(true)?, KeySource::Entered));
    }

    let key = generate_key()?;
    println!("Key generated (not displayed).");

    if confirm("Print the key?")? {
        let hex = Zeroizing::new(hex::encode(&key[..]));
        println!("\n    {}\n", hex.as_str());
        println!("Store this key somewhere safe. It will not be shown again, and");
        println!("without it the file cannot be decrypted.");
        Ok((key, KeySource::Generated { saved_to: None }))
    } else {
        let path = save_key_file(&key, input)?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        println!("Key saved as: {name}");
        println!("Keep this file safe: anyone who has it can decrypt the file, and");
        println!("without it the file cannot be decrypted.");
        Ok((key, KeySource::Generated { saved_to: Some(path) }))
    }
}

fn generate_key() -> Result<SecretKey> {
    let mut key: SecretKey = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    getrandom::fill(&mut key[..]).map_err(|e| format!("system random generator failed: {e}"))?;
    Ok(key)
}

/// Writes the raw key to `<input name>.key` in the working directory, adding a
/// number if that name is taken. Only the owner can read the file.
fn save_key_file(key: &[u8; KEY_LEN], input: &Path) -> Result<PathBuf> {
    let base = input
        .file_name()
        .map_or_else(|| "aes256".into(), |n| n.to_string_lossy().into_owned());
    let dir = std::env::current_dir()
        .map_err(|e| format!("cannot determine the working directory: {e}"))?;

    for n in 1..=1000 {
        let name = if n == 1 { format!("{base}.key") } else { format!("{base}.{n}.key") };
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(key).and_then(|()| file.sync_all()) {
                    let _ = fs::remove_file(&path);
                    return Err(format!("cannot write key file {}: {e}", path.display()));
                }
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create key file {}: {e}", path.display())),
        }
    }
    Err("no free key file name in the working directory".into())
}

/// Asks for a key, allowing three attempts. With `confirm_typed`, a hex key has
/// to be entered twice: the input is hidden, and encrypting with a mistyped key
/// would make the file unrecoverable.
fn prompt_key(confirm_typed: bool) -> Result<SecretKey> {
    for _ in 0..3 {
        let input = read_secret("Enter key (64 hex characters, or path to a key file): ")?;
        let key = match parse_key(&input) {
            Ok(key) => key,
            Err(e) => {
                println!("  {e}");
                continue;
            }
        };
        let typed = input.bytes().all(|b| b.is_ascii_hexdigit());
        if !confirm_typed || !typed {
            return Ok(key);
        }
        let again = read_secret("Re-enter the key to confirm: ")?;
        if parse_key(&again).is_ok_and(|k| *k == *key) {
            return Ok(key);
        }
        println!("  the keys did not match");
    }
    Err("no valid key entered".into())
}

/// Accepts 64 hex characters or the path to a 32-byte binary key file. Error
/// messages never echo the input, since it may be a mistyped key.
fn parse_key(input: &str) -> Result<SecretKey> {
    let mut key: SecretKey = Box::new(Zeroizing::new([0u8; KEY_LEN]));

    if !input.is_empty() && input.bytes().all(|b| b.is_ascii_hexdigit()) {
        if input.len() != 2 * KEY_LEN {
            return Err(format!(
                "a hex key must be {} characters; that was {}",
                2 * KEY_LEN,
                input.len()
            ));
        }
        hex::decode_to_slice(input, &mut key[..]).map_err(|e| format!("invalid hex key: {e}"))?;
        return Ok(key);
    }

    let path = clean_path(input);
    let invalid = || "not a valid key: expected 64 hex characters or the path to a key file".to_string();
    let mut file = File::open(&path).map_err(|_| invalid())?;
    let meta = file.metadata().map_err(|_| invalid())?;
    if !meta.is_file() {
        return Err(invalid());
    }
    if meta.len() != KEY_LEN as u64 {
        return Err(format!("a key file must be exactly {KEY_LEN} bytes; that one is {}", meta.len()));
    }
    file.read_exact(&mut key[..]).map_err(|e| format!("cannot read key file: {e}"))?;
    Ok(key)
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
    getrandom::fill(&mut header[NONCE_START..])
        .map_err(|e| format!("system random generator failed: {e}"))?;

    let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).expect("nonce is 12 bytes");
    let tag = Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce, &header, data.into())
        .map_err(|_| "encryption failed".to_string())?;
    Ok((header, tag.into()))
}

/// Authenticates and decrypts a complete encrypted file image in place and
/// returns just the plaintext. Fails if the key is wrong or any byte of the
/// header, ciphertext or tag has changed.
fn open(key: &[u8; KEY_LEN], mut blob: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err("file is too short to be an encrypted file".into());
    }
    check_header(&blob)?;

    let body_len = blob.len() - HEADER_LEN - TAG_LEN;
    let (header, rest) = blob.split_at_mut(HEADER_LEN);
    let (body, tag) = rest.split_at_mut(body_len);
    let header = &*header;
    let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).expect("nonce is 12 bytes");
    let tag = <&Tag<Aes256Gcm>>::try_from(&*tag).expect("tag is 16 bytes");

    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(nonce, header, body.into(), tag)
        .map_err(|_| {
            "authentication failed: wrong key, or the file is corrupted or has been tampered with"
                .to_string()
        })?;

    blob.copy_within(HEADER_LEN..HEADER_LEN + body_len, 0);
    blob.truncate(body_len);
    Ok(blob)
}

fn check_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < HEADER_LEN || bytes[..MAGIC.len()] != MAGIC[..] {
        return Err("not a file encrypted by this tool (missing AGCM header)".into());
    }
    match bytes[NONCE_START - 1] {
        VERSION => Ok(()),
        v => Err(format!("unsupported encrypted file version {v}")),
    }
}

fn verify_encrypted(key: &[u8; KEY_LEN], path: &Path, len: usize, hash: &[u8; 32]) -> Result<()> {
    let plain = open(key, read_file(path)?).map_err(|e| format!("verification failed: {e}"))?;
    if plain.len() != len || sha256(&plain) != *hash {
        return Err("verification failed: decrypted file does not match the original".into());
    }
    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let err = |e: io::Error| format!("cannot re-read {}: {e}", path.display());
    let mut file = File::open(path).map_err(err)?;
    let mut buf = Zeroizing::new(vec![0u8; 1 << 16]);
    let mut hasher = Sha256::new();
    loop {
        let n = file.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

fn regular_file_len(path: &Path) -> Result<u64> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symbolic link; give the path of the file it points to",
            path.display()
        ));
    }
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(meta.len())
}

/// Reads a whole file into a buffer that is zeroed when dropped. The buffer is
/// sized up front so it never reallocates and leaves stray copies behind.
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let err = |e: io::Error| format!("cannot read {}: {e}", path.display());
    let mut file = File::open(path).map_err(err)?;
    let len = file.metadata().map_err(err)?.len();
    let cap = usize::try_from(len).map_err(|_| format!("{} is too large", path.display()))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    file.read_to_end(&mut buf).map_err(err)?;
    Ok(buf)
}

/// Writes `parts` to `path` through a temporary file in the same directory, so
/// a crash never leaves a half-written file under the final name. New files
/// are readable by the owner only.
fn write_file(path: &Path, parts: &[&[u8]], replace: bool) -> Result<()> {
    if !replace && path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let tmp = with_suffix(path, &format!(".{}.part", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    let written = parts
        .iter()
        .try_for_each(|part| file.write_all(part))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    Ok(())
}

/// Overwrites the original with zeros, flushes it to disk and deletes it, and
/// describes the outcome for the report. The overwrite is best effort: SSD
/// wear levelling and copy-on-write filesystems can keep the old blocks.
fn shred_and_delete(path: &Path) -> String {
    let overwritten = overwrite_with_zeros(path).is_ok();
    match fs::remove_file(path) {
        Ok(()) if overwritten => "overwritten with zeros, then deleted".into(),
        Ok(()) => "deleted (could not overwrite it first)".into(),
        Err(e) => format!("WARNING: could not delete it ({e}); delete it yourself"),
    }
}

fn overwrite_with_zeros(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; 1 << 16];
    let mut remaining = file.metadata()?.len();
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    file.sync_all()
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
// Terminal I/O
// ---------------------------------------------------------------------------

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| format!("cannot write to terminal: {e}"))?;
    let mut line = Zeroizing::new(String::new());
    let n = io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read input: {e}"))?;
    if n == 0 {
        return Err("input ended unexpectedly".into());
    }
    Ok(line.trim().to_owned())
}

fn confirm(question: &str) -> Result<bool> {
    loop {
        match ask(&format!("{question} [y/n]: "))?.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  please answer y or n"),
        }
    }
}

/// Reads a line without echoing it when attached to a terminal. Piped input is
/// read as-is so the tool can be scripted.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let line = if io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).map_err(|e| format!("cannot read key: {e}"))?
    } else {
        ask(prompt)?
    };
    let line = Zeroizing::new(line);
    Ok(Zeroizing::new(line.trim().to_owned()))
}

fn file_path(arg: Option<&str>, prompt: &str) -> Result<PathBuf> {
    match arg {
        Some(arg) => Ok(PathBuf::from(arg)),
        None => {
            let raw = ask(prompt)?;
            if raw.is_empty() {
                return Err("no file given".into());
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

    fn encrypt(key: &[u8; KEY_LEN], plain: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut data = plain.to_vec();
        let (header, tag) = seal(key, &mut data).unwrap();
        Zeroizing::new([&header[..], &data, &tag].concat())
    }

    #[test]
    fn round_trips_all_sizes() {
        let k = key(7);
        for len in [0, 1, 15, 16, 17, 4096, 100_003] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = encrypt(&k, &plain);
            assert_eq!(blob.len(), HEADER_LEN + len + TAG_LEN);
            assert_eq!(&open(&k, blob).unwrap()[..], &plain[..]);
        }
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
        let k = parse_key(hex).unwrap();
        assert_eq!(k[0], 0x00);
        assert_eq!(k[15], 0xff);
        assert_eq!(k[16], 0xff);
        assert!(parse_key(&hex[1..]).is_err());
        assert!(parse_key("").is_err());
        assert!(parse_key("not a key").is_err());
    }

    #[test]
    fn reads_key_files() {
        let dir = std::env::temp_dir().join(format!("aes256-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.key");
        let bad = dir.join("bad.key");
        fs::write(&good, [9u8; KEY_LEN]).unwrap();
        fs::write(&bad, [9u8; KEY_LEN - 1]).unwrap();

        assert_eq!(**parse_key(good.to_str().unwrap()).unwrap(), [9u8; KEY_LEN]);
        assert!(parse_key(bad.to_str().unwrap()).unwrap_err().contains("exactly 32 bytes"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn names_decrypted_files() {
        assert_eq!(decrypted_path(Path::new("a/report.pdf.enc")), Path::new("a/report.pdf"));
        assert_eq!(decrypted_path(Path::new("notes")), Path::new("notes.dec"));
    }
}
