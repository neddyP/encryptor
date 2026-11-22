//! The .encryptor file `encrypt -r` leaves in each folder it encrypts files
//! in. It lists the folder's .enc files in groups, one group per key or
//! passphrase, each with a fingerprint of it, so `decrypt -r` can ask for
//! each group's key once and check it before using it. It never holds a key.
//!
//! It's plain text:
//!
//! ```text
//! encryptor-manifest 1
//!
//! key <fingerprint: 64 hex>
//!   report.pdf.enc
//!   list.md.enc
//!
//! passphrase argon2id <memory KiB> <passes> <lanes> <salt: 64 hex> <fingerprint: 64 hex>
//!   notes.txt.enc
//! ```
//!
//! A key's fingerprint is HKDF-SHA256 of the key (info `encryptor key
//! fingerprint`). A random 256-bit key can't be found from it. A passphrase
//! could be guessed from a fast hash, so its fingerprint is made the slow way
//! a file's key is, with Argon2id and a salt of its own, then HKDF-SHA256
//! (info `encryptor passphrase fingerprint`): a guess costs as much against
//! it as against the files.
//!
//! Files are listed by name, indented two spaces, with `%`, control
//! characters and bytes that aren't UTF-8 written as `%XX`.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::Secret;
use crate::term::safe_path;
use crate::{KEY_LEN, files, kdf};

/// The file's name, in each folder.
pub const NAME: &str = ".encryptor";
const FIRST_LINE: &str = "encryptor-manifest 1";
const KEY_INFO: &[u8] = b"encryptor key fingerprint";
const PASSPHRASE_INFO: &[u8] = b"encryptor passphrase fingerprint";
/// Far more than any folder's list needs, so a huge file isn't read whole.
const MAX_LEN: u64 = 64 * 1024 * 1024;
const COMMENT: &str = "\
# encryptor: the .enc files in this folder, grouped by the key or passphrase
# that opens them. No key or passphrase is stored here. Each group's
# fingerprint lets decrypt -r check a key is right before using it; it can't
# be turned back into the key.
";

/// What a group's key or passphrase is checked against.
#[derive(Clone, Debug, PartialEq)]
pub enum Fingerprint {
    Key([u8; 32]),
    Passphrase { params: kdf::Params, salt: [u8; 32], hash: [u8; 32] },
}

impl Fingerprint {
    /// The fingerprint of a key.
    pub fn of_key(key: &[u8; KEY_LEN]) -> Self {
        Self::Key(expand(key, KEY_INFO))
    }

    /// A new fingerprint of a passphrase, with a salt of its own. It takes as
    /// long as making a file's key from it, about half a second.
    pub fn of_passphrase(passphrase: &[u8]) -> Result<Self> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|e| Error::Message(format!("couldn't get random bytes from the OS: {e}")))?;
        let params = kdf::DEFAULT;
        let hash = passphrase_hash(passphrase, &params, &salt)?;
        Ok(Self::Passphrase { params, salt, hash })
    }

    pub fn of_secret(secret: &Secret) -> Result<Self> {
        match secret {
            Secret::Key(key) => Ok(Self::of_key(key)),
            Secret::Passphrase(passphrase) => Self::of_passphrase(passphrase.as_bytes()),
        }
    }

    pub fn is_passphrase(&self) -> bool {
        matches!(self, Self::Passphrase { .. })
    }

    pub fn matches_key(&self, key: &[u8; KEY_LEN]) -> bool {
        matches!(self, Self::Key(hash) if *hash == expand(key, KEY_INFO))
    }

    /// Whether `passphrase` is this group's: as slow as making a key from it.
    pub fn matches_passphrase(&self, passphrase: &[u8]) -> Result<bool> {
        match self {
            Self::Passphrase { params, salt, hash } => Ok(passphrase_hash(passphrase, params, salt)? == *hash),
            Self::Key(_) => Ok(false),
        }
    }

    fn to_line(&self) -> String {
        match self {
            Self::Key(hash) => format!("key {}", hex::encode(hash)),
            Self::Passphrase { params, salt, hash } => format!(
                "passphrase argon2id {} {} {} {} {}",
                params.memory_kib,
                params.passes,
                params.lanes,
                hex::encode(salt),
                hex::encode(hash)
            ),
        }
    }

    fn from_line(line: &str) -> Option<Self> {
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["key", hash] => Some(Self::Key(hex32(hash)?)),
            ["passphrase", "argon2id", memory, passes, lanes, salt, hash] => {
                let mut bytes = Vec::with_capacity(kdf::LEN);
                for word in [memory, passes, lanes] {
                    bytes.extend_from_slice(&word.parse::<u32>().ok()?.to_le_bytes());
                }
                let params = kdf::Params::from_bytes(&bytes)?;
                Some(Self::Passphrase { params, salt: hex32(salt)?, hash: hex32(hash)? })
            }
            _ => None,
        }
    }
}

fn expand(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm).expand(info, &mut out).expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

fn passphrase_hash(passphrase: &[u8], params: &kdf::Params, salt: &[u8; 32]) -> Result<[u8; 32]> {
    let stretched = kdf::derive(passphrase, params, salt)?;
    Ok(expand(&stretched[..], PASSPHRASE_INFO))
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// One key's files.
#[derive(Debug, PartialEq)]
pub struct Group {
    pub fingerprint: Fingerprint,
    pub files: Vec<OsString>,
}

/// A folder's .encryptor file.
#[derive(Default, Debug, PartialEq)]
pub struct Manifest {
    pub groups: Vec<Group>,
}

impl Manifest {
    /// Reads the text of a .encryptor file, or `None` if it isn't one this
    /// version understands.
    pub fn parse(text: &[u8]) -> Option<Self> {
        let mut manifest = Self::default();
        let mut started = false;
        for line in text.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            if !started {
                if line != FIRST_LINE.as_bytes() {
                    return None;
                }
                started = true;
            } else if let Some(name) = line.strip_prefix(b"  ") {
                let group = manifest.groups.last_mut()?;
                let name = unescape(name)?;
                if name.is_empty() || name.as_bytes().contains(&b'/') {
                    return None;
                }
                group.files.push(name);
            } else {
                let fingerprint = Fingerprint::from_line(std::str::from_utf8(line).ok()?)?;
                manifest.groups.push(Group { fingerprint, files: Vec::new() });
            }
        }
        started.then_some(manifest)
    }

    pub fn to_text(&self) -> Vec<u8> {
        let mut text = format!("{COMMENT}{FIRST_LINE}\n").into_bytes();
        for group in self.groups.iter().filter(|group| !group.files.is_empty()) {
            text.push(b'\n');
            text.extend_from_slice(group.fingerprint.to_line().as_bytes());
            text.push(b'\n');
            for name in &group.files {
                text.extend_from_slice(b"  ");
                text.extend_from_slice(escape(name).as_bytes());
                text.push(b'\n');
            }
        }
        text
    }

    /// Puts `name` in the group for `fingerprint`, starting one if there's
    /// none yet, and takes it out of any other: a file of that name was
    /// encrypted before, and this is the one there now.
    pub fn add(&mut self, name: &OsStr, fingerprint: &Fingerprint) {
        for group in &mut self.groups {
            group.files.retain(|listed| listed != name);
        }
        self.groups.retain(|group| !group.files.is_empty());
        match self.groups.iter_mut().find(|group| group.fingerprint == *fingerprint) {
            Some(group) => group.files.push(name.to_os_string()),
            None => self.groups.push(Group { fingerprint: fingerprint.clone(), files: vec![name.to_os_string()] }),
        }
    }

    /// The fingerprint of the group `name` is in, if it's listed.
    pub fn group_of(&self, name: &OsStr) -> Option<&Fingerprint> {
        self.groups.iter().find(|group| group.files.iter().any(|listed| listed == name)).map(|g| &g.fingerprint)
    }
}

/// `name` as it's written in the file: readable, on one line.
fn escape(name: &OsStr) -> String {
    let mut out = String::new();
    for chunk in name.as_bytes().utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '%' || c.is_control() {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            } else {
                out.push(c);
            }
        }
        for b in chunk.invalid() {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unescape(text: &[u8]) -> Option<OsString> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'%' {
            let digits = std::str::from_utf8(text.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            i += 3;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    Some(OsString::from_vec(out))
}

/// A folder's .encryptor file, as found.
pub enum Loaded {
    Missing,
    Read(Manifest),
    /// There, but unreadable or not one this version understands, with why.
    Unusable(String),
}

/// Reads the .encryptor file in `dir`. A link isn't followed.
pub fn load(dir: &Path) -> Loaded {
    let path = dir.join(NAME);
    let file = match files::open_no_follow(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Loaded::Missing,
        Err(e) => return Loaded::Unusable(format!("{}: {e}", safe_path(&path))),
    };
    let mut text = Vec::new();
    if let Err(e) = file.take(MAX_LEN).read_to_end(&mut text) {
        return Loaded::Unusable(format!("{}: {e}", safe_path(&path)));
    }
    match Manifest::parse(&text) {
        Some(manifest) => Loaded::Read(manifest),
        None => Loaded::Unusable(format!("{} isn't a key group list this version can read", safe_path(&path))),
    }
}

/// Writes `manifest` as the .encryptor file in `dir`, replacing it whole, so
/// it's never left half written. Only the owner can read it.
fn save(dir: &Path, manifest: &Manifest) -> io::Result<()> {
    let path = dir.join(NAME);
    let part = dir.join(format!("{NAME}.{}.part", std::process::id()));
    let written = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&part)?;
        file.write_all(&manifest.to_text())?;
        file.sync_all()?;
        fs::rename(&part, &path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&part);
    }
    written
}

/// What recording a run's files did.
pub struct Recorded {
    folders: usize,
    groups: usize,
    warnings: Vec<String>,
}

impl Recorded {
    /// For the report.
    pub fn row(&self) -> String {
        let plural = |n: usize, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
        let mut parts = Vec::new();
        if self.folders > 0 {
            parts.push(format!(
                "{NAME} updated in {}, listing {} (key fingerprints only, never a key)",
                plural(self.folders, "folder", "folders"),
                plural(self.groups, "key group", "key groups")
            ));
        }
        parts.extend(self.warnings.iter().map(|warning| format!("WARNING: {warning}")));
        parts.join("; ")
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Lists each encrypted file in its folder's .encryptor file, in the group
/// for its key. A file there that can't be read is left alone, and said so.
pub fn record(encrypted: &[(PathBuf, Fingerprint)]) -> Recorded {
    let mut by_folder: Vec<(PathBuf, Vec<(&OsStr, &Fingerprint)>)> = Vec::new();
    let mut index: HashMap<PathBuf, usize> = HashMap::new();
    let mut groups: Vec<&Fingerprint> = Vec::new();
    for (path, fingerprint) in encrypted {
        let Some(name) = path.file_name() else { continue };
        let dir = files::folder(path).to_path_buf();
        let i = *index.entry(dir.clone()).or_insert_with(|| {
            by_folder.push((dir, Vec::new()));
            by_folder.len() - 1
        });
        by_folder[i].1.push((name, fingerprint));
        if !groups.contains(&fingerprint) {
            groups.push(fingerprint);
        }
    }
    let mut recorded = Recorded { folders: 0, groups: groups.len(), warnings: Vec::new() };
    for (dir, entries) in by_folder {
        let mut manifest = match load(&dir) {
            Loaded::Missing => Manifest::default(),
            Loaded::Read(manifest) => manifest,
            Loaded::Unusable(why) => {
                recorded.warnings.push(format!("{why}, so it was left as it was and the files not added to it"));
                continue;
            }
        };
        for (name, fingerprint) in entries {
            manifest.add(name, fingerprint);
        }
        match save(&dir, &manifest) {
            Ok(()) => recorded.folders += 1,
            Err(e) => recorded.warnings.push(format!("couldn't write {}: {e}", safe_path(&dir.join(NAME)))),
        }
    }
    recorded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    fn name(text: &str) -> OsString {
        OsString::from(text)
    }

    #[test]
    fn checks_a_key_against_its_fingerprint() {
        let key = [7u8; KEY_LEN];
        let fingerprint = Fingerprint::of_key(&key);
        assert!(fingerprint.matches_key(&key));
        assert!(!fingerprint.matches_key(&[8u8; KEY_LEN]));
        // It isn't the key, or a plain hash of it.
        let Fingerprint::Key(hash) = &fingerprint else { panic!() };
        assert_ne!(hash, &key);
        assert_ne!(hash[..], files::sha256(&key)[..]);
    }

    #[test]
    fn checks_a_passphrase_slowly_against_its_own_salt() {
        let small = kdf::Params { memory_kib: 64, passes: 1, lanes: 1 };
        let salt = [3u8; 32];
        let hash = passphrase_hash(b"Correct horse 1!", &small, &salt).unwrap();
        let fingerprint = Fingerprint::Passphrase { params: small, salt, hash };
        assert!(fingerprint.matches_passphrase(b"Correct horse 1!").unwrap());
        assert!(!fingerprint.matches_passphrase(b"Correct horse 2!").unwrap());
        assert!(!fingerprint.matches_key(&[0; KEY_LEN]));
    }

    #[test]
    fn reads_back_what_it_writes() {
        let small = kdf::Params { memory_kib: 64, passes: 1, lanes: 1 };
        let mut manifest = Manifest::default();
        let key = Fingerprint::of_key(&[1; KEY_LEN]);
        let passphrase = Fingerprint::Passphrase { params: small, salt: [2; 32], hash: [3; 32] };
        manifest.add(&name("report.pdf.enc"), &key);
        manifest.add(&name("key 100%.enc"), &key);
        manifest.add(&name("  spaced\nline\u{7}.enc"), &passphrase);
        manifest.add(OsStr::from_bytes(b"bad\xffutf8.enc"), &passphrase);
        let text = manifest.to_text();
        assert_eq!(Manifest::parse(&text), Some(manifest));
        let shown = String::from_utf8(text).unwrap();
        assert!(shown.contains("\n  report.pdf.enc\n"), "{shown}");
        assert!(shown.contains("\n  key 100%25.enc\n"), "{shown}");
        assert!(shown.contains("\n    spaced%0Aline%07.enc\n"), "{shown}");
        assert!(shown.contains("\n  bad%FFutf8.enc\n"), "{shown}");
    }

    #[test]
    fn moves_a_file_encrypted_again_to_its_new_group() {
        let (one, two) = (Fingerprint::of_key(&[1; KEY_LEN]), Fingerprint::of_key(&[2; KEY_LEN]));
        let mut manifest = Manifest::default();
        manifest.add(&name("a.enc"), &one);
        manifest.add(&name("b.enc"), &one);
        manifest.add(&name("a.enc"), &two);
        manifest.add(&name("c.enc"), &one);
        assert_eq!(manifest.group_of(&name("a.enc")), Some(&two));
        assert_eq!(manifest.group_of(&name("c.enc")), Some(&one));
        assert_eq!(manifest.groups.len(), 2);
        manifest.add(&name("a.enc"), &one);
        assert_eq!(manifest.groups.len(), 1, "an emptied group is dropped");
    }

    #[test]
    fn refuses_what_it_does_not_understand() {
        assert_eq!(Manifest::parse(b""), None);
        assert_eq!(Manifest::parse(b"encryptor-manifest 2\n"), None);
        assert_eq!(Manifest::parse(b"encryptor-manifest 1\n  orphan.enc\n"), None);
        assert_eq!(Manifest::parse(b"encryptor-manifest 1\nkey 12\n"), None);
        let key = format!("encryptor-manifest 1\nkey {}\n", "ab".repeat(32));
        assert!(Manifest::parse(format!("{key}  ../escape.enc\n").as_bytes()).is_none());
        assert!(Manifest::parse(format!("{key}  bad%Z.enc\n").as_bytes()).is_none());
        assert!(Manifest::parse(format!("# note\n{key}  fine.enc\n").as_bytes()).is_some());
        let absurd = format!("encryptor-manifest 1\npassphrase argon2id 4294967295 3 1 {0} {0}\n", "ab".repeat(32));
        assert_eq!(Manifest::parse(absurd.as_bytes()), None);
    }

    #[test]
    fn records_each_file_in_its_own_folder() {
        let dir = Scratch::new("manifest-records");
        fs::create_dir(dir.join("sub")).unwrap();
        let (one, two) = (Fingerprint::of_key(&[1; KEY_LEN]), Fingerprint::of_key(&[2; KEY_LEN]));
        let recorded = record(&[(dir.join("a.enc"), one.clone()), (dir.join("sub/b.enc"), one.clone())]);
        assert_eq!((recorded.folders, recorded.groups), (2, 1));
        // A second run adds a group beside the first.
        record(&[(dir.join("c.enc"), two.clone())]);
        let Loaded::Read(top) = load(&dir) else { panic!() };
        assert_eq!(top.group_of(&name("a.enc")), Some(&one));
        assert_eq!(top.group_of(&name("c.enc")), Some(&two));
        let Loaded::Read(sub) = load(&dir.join("sub")) else { panic!() };
        assert_eq!(sub.groups.len(), 1);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join(NAME)).unwrap().permissions().mode() & 0o777, 0o600);

        // One it can't read is left as it was.
        fs::write(dir.join(NAME), "not a list").unwrap();
        let recorded = record(&[(dir.join("d.enc"), two)]);
        assert_eq!(recorded.folders, 0);
        assert!(recorded.row().contains("left as it was"), "{}", recorded.row());
        assert_eq!(fs::read(dir.join(NAME)).unwrap(), b"not a list");
    }
}
