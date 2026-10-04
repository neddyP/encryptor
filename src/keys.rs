//! Keys: generating, saving and printing them, and reading them as typed or
//! from a key file.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::cli::Options;
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::clean_path;
use crate::term::{self, Shown, choose, confirm, safe, safe_path};
use crate::{protect, recording, wipe};

/// Key bytes live on the heap, locked in RAM, so moving the handle never
/// copies the key and it is never swapped out. They are zeroed when dropped.
pub type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

pub enum KeySource {
    Generated { saved_to: Option<PathBuf>, printed: Printed },
    FromFile { path: PathBuf },
    Entered,
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
    pub fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for UnusedKeyFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            if wipe::shred(path).is_ok() {
                eprintln!("Shredded unused key file {}", safe_path(path));
            }
        }
    }
}

/// Gets the key to encrypt `input` with: the one in `--key-file`, a new one
/// saved to `--new-key`, or else a new random one, saved or printed as the
/// user chooses, or one they enter.
pub fn establish(input: &Path, key_file: &mut UnusedKeyFile, options: &Options) -> Result<(SecretKey, KeySource)> {
    if let Some(path) = &options.key_file {
        let key = read_key_file(path)?;
        return Ok((key, KeySource::FromFile { path: path.clone() }));
    }
    if let Some(destination) = &options.new_key {
        let key = generate()?;
        let path = match destination.is_dir() {
            true => write_key_file(&key, input, destination)?,
            false => write_key_file_at(&key, destination)?,
        };
        key_file.0 = Some(path.clone());
        return Ok((key, KeySource::Generated { saved_to: Some(path), printed: Printed::No }));
    }

    if !confirm("Generate a random 256-bit key?")? {
        let give_up = "no valid key after 3 attempts.\nRun encrypt again and answer y to have a random \
                       key generated, or enter a key of 64 characters, 0-9 and a-f.";
        let (key, _) = prompt(true, give_up)?;
        return Ok((key, KeySource::Entered));
    }

    let key = generate()?;
    eprintln!("Key generated (not displayed).");

    let mut saved_to = None;
    if confirm("Save symmetric encryption key as a file in your current directory?")? {
        saved_to = Some(save(&key, input, key_file)?);
    }
    let mut printed = if confirm("Print the key?")? { print(&key)? } else { Printed::No };

    // A key that is neither saved nor printed is gone once the program exits,
    // and the file with it, so one of the two is required.
    if saved_to.is_none() && printed == Printed::No {
        eprintln!();
        eprintln!("WARNING: the key has been neither saved nor printed. It exists only in");
        eprintln!("this program's memory, so the encrypted file could never be decrypted.");
        loop {
            if choose("Print or save the key?", &["print", "save"])? == "save" {
                saved_to = Some(save(&key, input, key_file)?);
                break;
            }
            printed = print(&key)?;
            if printed != Printed::No {
                break;
            }
        }
    }
    Ok((key, KeySource::Generated { saved_to, printed }))
}

/// Saves the key in the working directory, tells the user where, and hands
/// the file to `key_file` to shred if encryption doesn't complete.
fn save(key: &[u8; KEY_LEN], input: &Path, key_file: &mut UnusedKeyFile) -> Result<PathBuf> {
    let dir = std::env::current_dir().map_err(|e| Error::File(explain::no_working_folder(&e)))?;
    let path = write_key_file(key, input, &dir)?;
    key_file.0 = Some(path.clone());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    eprintln!("Key saved as: {}", safe(&name));
    eprintln!("Keep this file safe: anyone who has it can decrypt the file, and");
    eprintln!("without the key the file cannot be decrypted.");
    Ok(path)
}

/// Shows the key on the terminal and erases it afterwards, or explains why it
/// can't be shown here. If anything is recording the session, says what and
/// asks first.
fn print(key: &[u8; KEY_LEN]) -> Result<Printed> {
    let recorders = recording::scan();
    let captured_by = (!recorders.is_empty()).then(|| recording::names(&recorders));
    if let Some(by) = &captured_by {
        eprintln!();
        eprintln!("WARNING: something is recording or sharing this terminal session:");
        for recorder in &recorders {
            eprint!("{recorder}");
        }
        // Only someone at the keyboard can agree to this, not an answer piped
        // in, which could be meant for another question or be `yes`.
        if !io::stdin().is_terminal() {
            eprintln!("The key was not printed, since it would be captured and there's no one at the");
            eprintln!("keyboard to agree to that. Save it to a file instead, such as with --new-key.");
            return Ok(Printed::No);
        }
        if !confirm(&format!(
            "Printing the key would save it to {by} compromising your encryption, \
             do you still wish to print your decryption key?"
        ))? {
            eprintln!("Key not printed.");
            return Ok(Printed::No);
        }
    }
    match term::show_key(key)? {
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
fn new_key() -> SecretKey {
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
        let input = term::read_secret("Enter key (64 hex characters, or path to a key file from current directory): ")?;
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
    let path = Path::new(OsStr::from_bytes(&path_bytes));
    let file = File::open(path).map_err(|e| explain::not_a_key(input, path, &e))?;
    let key = key_from_file(path, file).map_err(|e| e.to_string())?;
    Ok((key, Some(path.to_path_buf())))
}

/// The key in a key file: 32 raw bytes, or 64 hex characters as printed, with
/// any whitespace around them. It may be a pipe, as with
/// `--key-file <(pass show keys/report)`, so its size isn't known in advance.
pub fn read_key_file(path: &Path) -> Result<SecretKey> {
    let file = File::open(path).map_err(|e| Error::File(explain::file(Action::Read, path, &e)))?;
    key_from_file(path, file)
}

fn key_from_file(path: &Path, mut file: File) -> Result<SecretKey> {
    let meta = file.metadata().map_err(|e| Error::File(explain::file(Action::Read, path, &e)))?;
    if meta.is_dir() {
        return Err(Error::File(explain::key_file_folder(path)));
    }
    // A key as hex text is at most 64 characters and a line break or two.
    let mut contents = Zeroizing::new([0u8; 2 * KEY_LEN + 3]);
    protect::lock(contents.as_ptr(), contents.len());
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
        let dir = std::env::temp_dir().join(format!("encryptor-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
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
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_keys_written_out_as_hex() {
        let dir = std::env::temp_dir().join(format!("encryptor-hexkey-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
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
        fs::remove_dir_all(&dir).unwrap();
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
