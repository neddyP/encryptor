//! The .encryptor file `encrypt -r` (and `encrypt --hide-names`) leaves in
//! each folder it encrypts files in. It lists the folder's .enc files in
//! groups, one group per key or passphrase, each with a fingerprint of it, so
//! `decrypt -r` can ask for each group's key once and check it before using
//! it. It never holds a key. A file given a random name has its real name
//! beside it, encrypted with its group's key.
//!
//! It's plain text:
//!
//! ```text
//! encryptor-manifest 1
//!
//! key <fingerprint: 64 hex>
//!   report.pdf.enc
//!   9f2c41a0d3e8b7c6f1a25e0d4b8c3f71.enc<TAB><encrypted real name: hex>
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
//! Real names are encrypted with AES-256-GCM under a key made the same way
//! with info `encryptor name key` (or `encryptor passphrase name key`): a
//! 12-byte random nonce, then the name encrypted, then the 16-byte tag, with
//! the .enc file's name as associated data, so a name can't be moved to
//! another file.
//!
//! Files are listed by name, indented two spaces, with `%`, control
//! characters (tabs too) and bytes that aren't UTF-8 written as `%XX`.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::Secret;
use crate::term::safe_path;
use crate::{KEY_LEN, files, kdf};

/// The file's name, in each folder.
pub const NAME: &str = ".encryptor";
const FIRST_LINE: &str = "encryptor-manifest 1";
const KEY_INFO: &[u8] = b"encryptor key fingerprint";
const PASSPHRASE_INFO: &[u8] = b"encryptor passphrase fingerprint";
const NAME_KEY_INFO: &[u8] = b"encryptor name key";
const PASSPHRASE_NAME_KEY_INFO: &[u8] = b"encryptor passphrase name key";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Far more than any folder's list needs, so a huge file isn't read whole.
pub const MAX_LEN: u64 = 64 * 1024 * 1024;
const COMMENT: &str = "\
# encryptor: the .enc files in this folder, grouped by the key or passphrase
# that opens them. No key or passphrase is stored here. Each group's
# fingerprint lets decrypt -r check a key is right before using it; it can't
# be turned back into the key. Real names of files with random names are
# encrypted with their group's key.
";

/// What a group's key or passphrase is checked against.
#[derive(Clone, Debug, PartialEq)]
pub enum Fingerprint {
    Key([u8; 32]),
    Passphrase { params: kdf::Params, salt: [u8; 32], hash: [u8; 32] },
}

/// A group's fingerprint with the key its real names are encrypted with,
/// which only the group's key or passphrase gives.
pub struct GroupKey {
    pub fingerprint: Fingerprint,
    names: Zeroizing<[u8; 32]>,
}

impl GroupKey {
    /// A key's group.
    pub fn of_key(key: &[u8; KEY_LEN]) -> Self {
        Self { fingerprint: Fingerprint::Key(expand(key, KEY_INFO)), names: Zeroizing::new(expand(key, NAME_KEY_INFO)) }
    }

    /// A new group for a passphrase, with a salt of its own. It takes as long
    /// as making a file's key from it, about half a second.
    pub fn of_passphrase(passphrase: &[u8]) -> Result<Self> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|e| Error::Message(format!("couldn't get random bytes from the OS: {e}")))?;
        Self::stretch(passphrase, kdf::DEFAULT, salt)
    }

    fn stretch(passphrase: &[u8], params: kdf::Params, salt: [u8; 32]) -> Result<Self> {
        let stretched = kdf::derive(passphrase, &params, &salt)?;
        Ok(Self {
            fingerprint: Fingerprint::Passphrase { params, salt, hash: expand(&stretched[..], PASSPHRASE_INFO) },
            names: Zeroizing::new(expand(&stretched[..], PASSPHRASE_NAME_KEY_INFO)),
        })
    }

    pub fn of_secret(secret: &Secret) -> Result<Self> {
        match secret {
            Secret::Key(key) => Ok(Self::of_key(key)),
            Secret::Passphrase(passphrase) => Self::of_passphrase(passphrase.as_bytes()),
        }
    }

    /// `real`, encrypted for the .enc file named `listed`.
    pub fn seal_name(&self, listed: &OsStr, real: &OsStr) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| Error::Message(format!("couldn't get random bytes from the OS: {e}")))?;
        let mut data = real.as_bytes().to_vec();
        let tag = Aes256Gcm::new((&*self.names).into())
            .encrypt_inout_detached(<&Nonce<Aes256Gcm>>::from(&nonce), listed.as_bytes(), data.as_mut_slice().into())
            .map_err(|_| Error::Message("couldn't encrypt the file's name".into()))?;
        Ok([&nonce[..], &data, &tag[..]].concat())
    }

    /// The real name in `sealed`, if it opens for the .enc file `listed`.
    pub fn open_name(&self, listed: &OsStr, sealed: &[u8]) -> Option<OsString> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let (data, tag) = rest.split_at(rest.len() - TAG_LEN);
        let mut data = data.to_vec();
        Aes256Gcm::new((&*self.names).into())
            .decrypt_inout_detached(
                <&Nonce<Aes256Gcm>>::try_from(nonce).ok()?,
                listed.as_bytes(),
                data.as_mut_slice().into(),
                <&Tag<Aes256Gcm>>::try_from(tag).ok()?,
            )
            .ok()?;
        Some(OsString::from_vec(data))
    }
}

impl Fingerprint {
    pub fn is_passphrase(&self) -> bool {
        matches!(self, Self::Passphrase { .. })
    }

    /// The group, if `key` is its key.
    pub fn unlock_key(&self, key: &[u8; KEY_LEN]) -> Option<GroupKey> {
        let group = GroupKey::of_key(key);
        (group.fingerprint == *self).then_some(group)
    }

    pub fn matches_key(&self, key: &[u8; KEY_LEN]) -> bool {
        self.unlock_key(key).is_some()
    }

    /// The group, if `passphrase` is its passphrase: as slow as making a key
    /// from it.
    pub fn unlock_passphrase(&self, passphrase: &[u8]) -> Result<Option<GroupKey>> {
        let Self::Passphrase { params, salt, .. } = self else { return Ok(None) };
        let group = GroupKey::stretch(passphrase, *params, *salt)?;
        Ok((group.fingerprint == *self).then_some(group))
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

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// A .enc file in a group, with its real name, encrypted, if it was given a
/// random one.
#[derive(Clone, Debug, PartialEq)]
pub struct Listed {
    pub name: OsString,
    pub hidden: Option<Vec<u8>>,
}

/// One key's files.
#[derive(Debug, PartialEq)]
pub struct Group {
    pub fingerprint: Fingerprint,
    pub files: Vec<Listed>,
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
            } else if let Some(entry) = line.strip_prefix(b"  ") {
                let group = manifest.groups.last_mut()?;
                let mut parts = entry.splitn(2, |&b| b == b'\t');
                let name = unescape(parts.next()?)?;
                if !plain_name(&name) {
                    return None;
                }
                let hidden = match parts.next() {
                    Some(sealed) => Some(hex::decode(sealed).ok()?),
                    None => None,
                };
                group.files.push(Listed { name, hidden });
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
            for listed in &group.files {
                text.extend_from_slice(b"  ");
                text.extend_from_slice(escape(&listed.name).as_bytes());
                if let Some(hidden) = &listed.hidden {
                    text.push(b'\t');
                    text.extend_from_slice(hex::encode(hidden).as_bytes());
                }
                text.push(b'\n');
            }
        }
        text
    }

    /// Puts `name` in the group for `fingerprint`, starting one if there's
    /// none yet, and takes it out of any other: a file of that name was
    /// encrypted before, and this is the one there now.
    pub fn add(&mut self, name: &OsStr, fingerprint: &Fingerprint, hidden: Option<Vec<u8>>) {
        for group in &mut self.groups {
            group.files.retain(|listed| listed.name != name);
        }
        self.groups.retain(|group| !group.files.is_empty());
        let listed = Listed { name: name.to_os_string(), hidden };
        match self.groups.iter_mut().find(|group| group.fingerprint == *fingerprint) {
            Some(group) => group.files.push(listed),
            None => self.groups.push(Group { fingerprint: fingerprint.clone(), files: vec![listed] }),
        }
    }

    /// The group `name` is in and its entry there, if it's listed.
    pub fn entry(&self, name: &OsStr) -> Option<(&Fingerprint, &Listed)> {
        self.groups.iter().find_map(|group| {
            group.files.iter().find(|listed| listed.name == name).map(|listed| (&group.fingerprint, listed))
        })
    }

    /// The fingerprint of the group `name` is in, if it's listed.
    pub fn group_of(&self, name: &OsStr) -> Option<&Fingerprint> {
        self.entry(name).map(|(fingerprint, _)| fingerprint)
    }
}

/// Whether `name` is a file's own name: not empty, `.` or `..`, and with no
/// `/` or zero byte, so it can't lead out of its folder.
pub fn plain_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.iter().any(|&b| b == b'/' || b == 0)
}

/// `name` as it's written in a list: readable, on one line, with no tabs.
pub fn escape(name: &OsStr) -> String {
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

pub fn unescape(text: &[u8]) -> Option<OsString> {
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

/// Reads the file at `path`, up to `MAX_LEN`, without following a link.
pub fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let file = files::open_no_follow(path)?;
    let mut text = Vec::new();
    file.take(MAX_LEN).read_to_end(&mut text)?;
    Ok(text)
}

/// Reads the .encryptor file in `dir`. A link isn't followed.
pub fn load(dir: &Path) -> Loaded {
    let path = dir.join(NAME);
    let text = match read_private(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Loaded::Missing,
        Err(e) => return Loaded::Unusable(format!("{}: {e}", safe_path(&path))),
    };
    match Manifest::parse(&text) {
        Some(manifest) => Loaded::Read(manifest),
        None => Loaded::Unusable(format!("{} isn't a key group list this version can read", safe_path(&path))),
    }
}

/// Writes `text` to `path`, replacing the file whole, so it's never left half
/// written. Only the owner can read it.
pub fn write_private(path: &Path, text: &[u8]) -> io::Result<()> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let part = files::folder(path).join(format!("{name}.{}.part", std::process::id()));
    let written = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&part)?;
        file.write_all(text)?;
        file.sync_all()?;
        fs::rename(&part, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&part);
    }
    written
}

/// A .enc file to list: where it is, its group, and with a random name, its
/// real name sealed with the group's key.
pub struct Entry {
    pub output: PathBuf,
    pub fingerprint: Fingerprint,
    pub hidden: Option<Vec<u8>>,
}

impl Entry {
    /// The entry for `output`, in `group`, with `real` sealed when it's
    /// given a random name.
    pub fn new(output: &Path, group: &GroupKey, real: Option<&OsStr>) -> Result<Self> {
        let hidden = match real {
            Some(real) => Some(group.seal_name(output.file_name().unwrap_or_default(), real)?),
            None => None,
        };
        Ok(Self { output: output.to_path_buf(), fingerprint: group.fingerprint.clone(), hidden })
    }
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

    /// Nothing recorded, for `why`.
    pub fn failed(why: String) -> Self {
        Self { folders: 0, groups: 0, warnings: vec![why] }
    }

    /// Adds warnings about entries that couldn't be made.
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings.extend(warnings);
        self
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Lists each encrypted file in its folder's .encryptor file, in the group
/// for its key. A file there that can't be read is left alone, and said so.
pub fn record(encrypted: &[Entry]) -> Recorded {
    let mut by_folder: Vec<(PathBuf, Vec<&Entry>)> = Vec::new();
    let mut index: HashMap<PathBuf, usize> = HashMap::new();
    let mut groups: Vec<&Fingerprint> = Vec::new();
    for entry in encrypted {
        if entry.output.file_name().is_none() {
            continue;
        }
        let dir = files::folder(&entry.output).to_path_buf();
        let i = *index.entry(dir.clone()).or_insert_with(|| {
            by_folder.push((dir, Vec::new()));
            by_folder.len() - 1
        });
        by_folder[i].1.push(entry);
        if !groups.contains(&&entry.fingerprint) {
            groups.push(&entry.fingerprint);
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
        for entry in entries {
            let name = entry.output.file_name().unwrap_or_default();
            manifest.add(name, &entry.fingerprint, entry.hidden.clone());
        }
        match write_private(&dir.join(NAME), &manifest.to_text()) {
            Ok(()) => recorded.folders += 1,
            Err(e) => recorded.warnings.push(format!("couldn't write {}: {e}", safe_path(&dir.join(NAME)))),
        }
    }
    recorded
}

/// Lists one encrypted file, `output`, in `group`, with `real` sealed when
/// it was given a random name.
pub fn record_one(output: &Path, group: &GroupKey, real: Option<&OsStr>) -> Recorded {
    match Entry::new(output, group, real) {
        Ok(entry) => record(&[entry]),
        Err(e) => Recorded::failed(format!("{NAME} wasn't updated: {e}")),
    }
}

/// Whether the .encryptor file beside `enc` lists it.
pub fn lists(enc: &Path) -> bool {
    match (load(files::folder(enc)), enc.file_name()) {
        (Loaded::Read(manifest), Some(name)) => manifest.entry(name).is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    fn name(text: &str) -> OsString {
        OsString::from(text)
    }

    fn small_passphrase_group(passphrase: &[u8]) -> GroupKey {
        GroupKey::stretch(passphrase, kdf::Params { memory_kib: 64, passes: 1, lanes: 1 }, [3; 32]).unwrap()
    }

    #[test]
    fn checks_a_key_against_its_fingerprint() {
        let key = [7u8; KEY_LEN];
        let fingerprint = GroupKey::of_key(&key).fingerprint;
        assert!(fingerprint.matches_key(&key));
        assert!(!fingerprint.matches_key(&[8u8; KEY_LEN]));
        // It isn't the key, or a plain hash of it.
        let Fingerprint::Key(hash) = &fingerprint else { panic!() };
        assert_ne!(hash, &key);
        assert_ne!(hash[..], files::sha256(&key)[..]);
    }

    #[test]
    fn checks_a_passphrase_slowly_against_its_own_salt() {
        let fingerprint = small_passphrase_group(b"Correct horse 1!").fingerprint;
        assert!(fingerprint.unlock_passphrase(b"Correct horse 1!").unwrap().is_some());
        assert!(fingerprint.unlock_passphrase(b"Correct horse 2!").unwrap().is_none());
        assert!(!fingerprint.matches_key(&[0; KEY_LEN]));
    }

    #[test]
    fn hides_real_names_from_all_but_the_group_key() {
        let group = GroupKey::of_key(&[1; KEY_LEN]);
        let listed = name("9f2c41a0d3e8b7c6f1a25e0d4b8c3f71.enc");
        let sealed = group.seal_name(&listed, &name("taxes 2024.pdf")).unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"taxes"));
        assert_eq!(group.open_name(&listed, &sealed), Some(name("taxes 2024.pdf")));
        // Only with its group's key, and only for the file it was sealed for.
        assert_eq!(GroupKey::of_key(&[2; KEY_LEN]).open_name(&listed, &sealed), None);
        assert_eq!(group.open_name(&name("other.enc"), &sealed), None);
        // A passphrase's group gives the same name key each time it's unlocked.
        let passphrase = small_passphrase_group(b"Correct horse 1!");
        let sealed = passphrase.seal_name(&listed, &name("notes.txt")).unwrap();
        let again = passphrase.fingerprint.unlock_passphrase(b"Correct horse 1!").unwrap().unwrap();
        assert_eq!(again.open_name(&listed, &sealed), Some(name("notes.txt")));
    }

    #[test]
    fn reads_back_what_it_writes() {
        let mut manifest = Manifest::default();
        let key = GroupKey::of_key(&[1; KEY_LEN]).fingerprint;
        let small = kdf::Params { memory_kib: 64, passes: 1, lanes: 1 };
        let passphrase = Fingerprint::Passphrase { params: small, salt: [2; 32], hash: [3; 32] };
        manifest.add(&name("report.pdf.enc"), &key, None);
        manifest.add(&name("key 100%.enc"), &key, Some(vec![1, 2, 3]));
        manifest.add(&name("  spaced\nline\t\u{7}.enc"), &passphrase, None);
        manifest.add(OsStr::from_bytes(b"bad\xffutf8.enc"), &passphrase, None);
        let text = manifest.to_text();
        assert_eq!(Manifest::parse(&text), Some(manifest));
        let shown = String::from_utf8(text).unwrap();
        assert!(shown.contains("\n  report.pdf.enc\n"), "{shown}");
        assert!(shown.contains("\n  key 100%25.enc\t010203\n"), "{shown}");
        assert!(shown.contains("\n    spaced%0Aline%09%07.enc\n"), "{shown}");
        assert!(shown.contains("\n  bad%FFutf8.enc\n"), "{shown}");
    }

    #[test]
    fn moves_a_file_encrypted_again_to_its_new_group() {
        let one = GroupKey::of_key(&[1; KEY_LEN]).fingerprint;
        let two = GroupKey::of_key(&[2; KEY_LEN]).fingerprint;
        let mut manifest = Manifest::default();
        manifest.add(&name("a.enc"), &one, None);
        manifest.add(&name("b.enc"), &one, None);
        manifest.add(&name("a.enc"), &two, None);
        manifest.add(&name("c.enc"), &one, None);
        assert_eq!(manifest.group_of(&name("a.enc")), Some(&two));
        assert_eq!(manifest.group_of(&name("c.enc")), Some(&one));
        assert_eq!(manifest.groups.len(), 2);
        manifest.add(&name("a.enc"), &one, None);
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
        assert!(Manifest::parse(format!("{key}  ..\n").as_bytes()).is_none());
        assert!(Manifest::parse(format!("{key}  bad%Z.enc\n").as_bytes()).is_none());
        assert!(Manifest::parse(format!("{key}  a.enc\tnot hex\n").as_bytes()).is_none());
        assert!(Manifest::parse(format!("# note\n{key}  fine.enc\n").as_bytes()).is_some());
        let absurd = format!("encryptor-manifest 1\npassphrase argon2id 4294967295 3 1 {0} {0}\n", "ab".repeat(32));
        assert_eq!(Manifest::parse(absurd.as_bytes()), None);
    }

    #[test]
    fn records_each_file_in_its_own_folder() {
        let dir = Scratch::new("manifest-records");
        fs::create_dir(dir.join("sub")).unwrap();
        let (one, two) = (GroupKey::of_key(&[1; KEY_LEN]), GroupKey::of_key(&[2; KEY_LEN]));
        let entry = |path: &str, group: &GroupKey| Entry::new(&dir.join(path), group, None).unwrap();
        let recorded = record(&[entry("a.enc", &one), entry("sub/b.enc", &one)]);
        assert_eq!((recorded.folders, recorded.groups), (2, 1));
        // A second run adds a group beside the first.
        record(&[entry("c.enc", &two)]);
        let Loaded::Read(top) = load(&dir) else { panic!() };
        assert_eq!(top.group_of(&name("a.enc")), Some(&one.fingerprint));
        assert_eq!(top.group_of(&name("c.enc")), Some(&two.fingerprint));
        assert!(lists(&dir.join("a.enc")) && !lists(&dir.join("z.enc")));
        let Loaded::Read(sub) = load(&dir.join("sub")) else { panic!() };
        assert_eq!(sub.groups.len(), 1);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join(NAME)).unwrap().permissions().mode() & 0o777, 0o600);

        // One it can't read is left as it was.
        fs::write(dir.join(NAME), "not a list").unwrap();
        let recorded = record(&[entry("d.enc", &two)]);
        assert_eq!(recorded.folders, 0);
        assert!(recorded.row().contains("left as it was"), "{}", recorded.row());
        assert_eq!(fs::read(dir.join(NAME)).unwrap(), b"not a list");
    }
}
