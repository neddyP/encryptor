//! Random names, for `encrypt --hide-names`: each .enc file is named with 16
//! random bytes, as 32 hex characters, so its name says nothing about what's
//! in it. Its real name is kept in two places:
//!
//! - its folder's .encryptor file, encrypted with its key group's key (see
//!   manifest.rs), so it travels with the folder and only its key reveals it;
//! - a list in `~/.local/share/encryptor/filenames`, one file per folder
//!   name, `.<folder name>`, readable only by you, so it's found on this
//!   computer without a key.
//!
//! The list is plain text:
//!
//! ```text
//! encryptor-filenames 1
//!
//! /home/you/Documents/taxes
//!   9f2c41a0d3e8b7c6f1a25e0d4b8c3f71.enc<TAB>2024.pdf
//! ```
//!
//! Folders are written as they really are, unindented; their files indented
//! two spaces, escaped as in .encryptor files. Two folders of the same name
//! share a list, each under its own path. A random name is never repeated,
//! so a file is found even after its folder is moved or renamed.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::KEY_LEN;
use crate::error::{Error, Result};
use crate::files;
use crate::keys;
use crate::manifest::{self, GroupKey, Loaded};
use crate::term::safe_path;

/// How many random bytes name a file.
pub const NAME_BYTES: usize = 16;
const FIRST_LINE: &str = "encryptor-filenames 1";
const COMMENT: &str = "\
# encryptor: the real names of files encrypt --hide-names gave random names,
# by the folder they're in. decrypt reads it to give them their names back.
";

/// Where the lists are kept: always `~/.local/share/encryptor/filenames`.
pub fn folder() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share/encryptor/filenames"))
}

/// The lists' folder, made if it isn't there yet, and checked to be the
/// user's own that only they can open.
pub fn open_folder() -> Result<PathBuf> {
    let dir = folder().ok_or_else(|| Error::File(crate::explain::NO_KEYS_FOLDER.into()))?;
    keys::private_folder(&dir)?;
    Ok(dir)
}

/// A new random name for the .enc file of `input`, beside it.
pub fn random_name(input: &Path) -> Result<PathBuf> {
    let mut bytes = [0u8; NAME_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| Error::Message(format!("couldn't get random bytes from the OS: {e}")))?;
    Ok(files::folder(input).join(format!("{}.{}", hex::encode(bytes), files::ENC_EXT)))
}

/// Whether `name` looks like a random name: 32 hex characters, then `.enc`.
pub fn is_random(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    let ext = format!(".{}", files::ENC_EXT);
    bytes.len() == 2 * NAME_BYTES + ext.len()
        && bytes.ends_with(ext.as_bytes())
        && bytes[..2 * NAME_BYTES].iter().all(u8::is_ascii_hexdigit)
}

/// One list file: folders, each with its random names and their real names.
#[derive(Default, Debug, PartialEq)]
struct List {
    folders: Vec<(OsString, Vec<(OsString, OsString)>)>,
}

impl List {
    fn parse(text: &[u8]) -> Option<Self> {
        let mut list = Self::default();
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
                let (_, names) = list.folders.last_mut()?;
                let tab = entry.iter().position(|&b| b == b'\t')?;
                let random = manifest::unescape(&entry[..tab])?;
                let real = manifest::unescape(&entry[tab + 1..])?;
                if !manifest::plain_name(&random) || !manifest::plain_name(&real) {
                    return None;
                }
                names.push((random, real));
            } else {
                list.folders.push((manifest::unescape(line)?, Vec::new()));
            }
        }
        started.then_some(list)
    }

    fn to_text(&self) -> Vec<u8> {
        let mut text = format!("{COMMENT}{FIRST_LINE}\n").into_bytes();
        for (dir, names) in self.folders.iter().filter(|(_, names)| !names.is_empty()) {
            text.push(b'\n');
            text.extend_from_slice(manifest::escape(dir).as_bytes());
            text.push(b'\n');
            for (random, real) in names {
                text.extend_from_slice(format!("  {}\t{}\n", manifest::escape(random), manifest::escape(real)).as_bytes());
            }
        }
        text
    }

    fn add(&mut self, dir: &OsStr, random: &OsStr, real: &OsStr) {
        let i = match self.folders.iter().position(|(listed, _)| listed == dir) {
            Some(i) => i,
            None => {
                self.folders.push((dir.to_os_string(), Vec::new()));
                self.folders.len() - 1
            }
        };
        let names = &mut self.folders[i].1;
        names.retain(|(listed, _)| listed != random);
        names.push((random.to_os_string(), real.to_os_string()));
    }

    /// The real name of `random`, preferring the entry under `dir`.
    fn find(&self, dir: Option<&OsStr>, random: &OsStr) -> Option<OsString> {
        let in_folder = |names: &[(OsString, OsString)]| {
            names.iter().find(|(listed, _)| listed == random).map(|(_, real)| real.clone())
        };
        let here = self.folders.iter().find(|(listed, _)| Some(listed.as_os_str()) == dir);
        here.and_then(|(_, names)| in_folder(names))
            .or_else(|| self.folders.iter().find_map(|(_, names)| in_folder(names)))
    }
}

/// The list for the real folder `dir`, named after it.
fn list_path(lists: &Path, dir: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(dir.file_name().unwrap_or(OsStr::new("root")));
    lists.join(name)
}

fn load(path: &Path) -> io::Result<Option<List>> {
    match manifest::read_private(path) {
        Ok(text) => Ok(List::parse(&text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Some(List::default())),
        Err(e) => Err(e),
    }
}

/// Adds each `(.enc file, real name)` to its folder's list. Returns what
/// went wrong, if anything did: the names are in .encryptor files too.
pub fn remember(hidden: &[(PathBuf, OsString)]) -> Vec<String> {
    let mut warnings = Vec::new();
    let lists = match open_folder() {
        Ok(lists) => lists,
        Err(e) => return vec![format!("the real names weren't added to the list in the filenames folder: {e}")],
    };
    let mut by_list: HashMap<PathBuf, List> = HashMap::new();
    let mut unusable = Vec::new();
    for (enc, real) in hidden {
        let (Ok(dir), Some(random)) = (fs::canonicalize(files::folder(enc)), enc.file_name()) else { continue };
        let path = list_path(&lists, &dir);
        if unusable.contains(&path) {
            continue;
        }
        if !by_list.contains_key(&path) {
            match load(&path) {
                Ok(Some(list)) => {
                    by_list.insert(path.clone(), list);
                }
                Ok(None) => {
                    warnings.push(format!(
                        "{} isn't a list of names this version can read, so it was left as it was",
                        safe_path(&path)
                    ));
                    unusable.push(path);
                    continue;
                }
                Err(e) => {
                    warnings.push(format!("couldn't read {}: {e}", safe_path(&path)));
                    unusable.push(path);
                    continue;
                }
            }
        }
        by_list.get_mut(&path).expect("loaded above").add(dir.as_os_str(), random, real);
    }
    for (path, list) in by_list {
        if let Err(e) = manifest::write_private(&path, &list.to_text()) {
            warnings.push(format!("couldn't write {}: {e}", safe_path(&path)));
        }
    }
    warnings
}

/// The report's row on random names.
pub const REPORT_ROW: &str = "hidden: named with 16 random bytes; the real name is kept in \
     ~/.local/share/encryptor/filenames, and encrypted with its key in its folder's .encryptor file";

/// Saves the real names of `hidden` to the lists, or stops the run before
/// anything is encrypted: a file whose real name was saved nowhere would
/// lose it.
pub fn save_or_stop(hidden: &[(PathBuf, OsString)]) -> Result<()> {
    let warnings = remember(hidden);
    if warnings.is_empty() {
        return Ok(());
    }
    Err(Error::File(format!(
        "{}.\nThe real names couldn't be saved, so nothing was encrypted. Fix that, or encrypt without \
         --hide-names.",
        warnings.join("; ")
    )))
}

/// Takes the .enc files `removed`, decrypted and shredded, out of the lists
/// of names, removing a list left empty. Returns what went wrong, if
/// anything did.
pub fn forget(removed: &[PathBuf]) -> Vec<String> {
    let Some(lists) = folder() else { return Vec::new() };
    let mut by_list: HashMap<PathBuf, Vec<&OsStr>> = HashMap::new();
    for enc in removed {
        let (Ok(dir), Some(random)) = (fs::canonicalize(files::folder(enc)), enc.file_name()) else { continue };
        if is_random(random) {
            by_list.entry(list_path(&lists, &dir)).or_default().push(random);
        }
    }
    let mut warnings = Vec::new();
    for (path, randoms) in by_list {
        let Ok(Some(mut list)) = load(&path) else { continue };
        for (_, names) in &mut list.folders {
            names.retain(|(random, _)| !randoms.contains(&random.as_os_str()));
        }
        list.folders.retain(|(_, names)| !names.is_empty());
        let done = match list.folders.is_empty() {
            true => fs::remove_file(&path).or_else(|e| if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
            false => manifest::write_private(&path, &list.to_text()),
        };
        if let Err(e) = done {
            warnings.push(format!("couldn't update {}: {e}", safe_path(&path)));
        }
    }
    warnings
}

/// Forgets the .enc files `removed` in both their .encryptor files and the
/// lists, warning of anything that went wrong.
pub fn forget_all(removed: &[PathBuf]) {
    for warning in manifest::forget(removed).into_iter().chain(forget(removed)) {
        eprintln!("warning: {warning}");
    }
}

/// The real name the lists hold for the .enc file `enc`: in its folder's
/// list, or, if its folder was moved or renamed, in any list.
pub fn recall(enc: &Path) -> Option<OsString> {
    let random = enc.file_name()?;
    let lists = folder()?;
    let dir = fs::canonicalize(files::folder(enc)).ok();
    if let Some(dir) = &dir
        && let Ok(Some(list)) = load(&list_path(&lists, dir))
        && let Some(real) = list.find(Some(dir.as_os_str()), random)
    {
        return Some(real);
    }
    let mut others: Vec<PathBuf> = fs::read_dir(&lists).ok()?.filter_map(|entry| Some(entry.ok()?.path())).collect();
    others.sort();
    others.iter().find_map(|path| load(path).ok().flatten()?.find(None, random))
}

/// What a group's real names may be unlocked with.
pub enum Unlock<'a> {
    Key(&'a [u8; KEY_LEN]),
    Passphrase(&'a [u8]),
    /// Nothing that can: a passphrase's file whose passphrase isn't at hand.
    Nothing,
}

/// Finds the real names of .enc files: in their folder's .encryptor file,
/// once their group's key is in hand, or else in the lists.
#[derive(Default)]
pub struct Namer {
    manifests: HashMap<PathBuf, Loaded>,
    groups: Vec<GroupKey>,
}

impl Namer {
    /// Takes a group's key, for the names it hides.
    pub fn unlocked(&mut self, group: GroupKey) {
        if !self.groups.iter().any(|known| known.fingerprint == group.fingerprint) {
            self.groups.push(group);
        }
    }

    /// The fingerprint and hidden name .encryptor holds for `enc`, if any.
    fn hidden(&mut self, enc: &Path) -> Option<(manifest::Fingerprint, Vec<u8>)> {
        let name = enc.file_name()?;
        let loaded = self.manifests.entry(files::folder(enc).to_path_buf()).or_insert_with_key(|dir| manifest::load(dir));
        let Loaded::Read(list) = loaded else { return None };
        let (fingerprint, listed) = list.entry(name)?;
        Some((fingerprint.clone(), listed.hidden.clone()?))
    }

    /// Unlocks the group hiding `enc`'s name with `with`, if it's that
    /// group's. A passphrase takes as long as making a key from it.
    pub fn unlock(&mut self, enc: &Path, with: Unlock) -> Result<()> {
        let Some((fingerprint, _)) = self.hidden(enc) else { return Ok(()) };
        if self.groups.iter().any(|group| group.fingerprint == fingerprint) {
            return Ok(());
        }
        let group = match with {
            Unlock::Key(key) => fingerprint.unlock_key(key),
            Unlock::Passphrase(passphrase) => fingerprint.unlock_passphrase(passphrase)?,
            Unlock::Nothing => None,
        };
        if let Some(group) = group {
            self.groups.push(group);
        }
        Ok(())
    }

    /// `enc`'s real name, if it was given a random one and it can be found.
    pub fn real_name(&mut self, enc: &Path) -> Option<OsString> {
        let name = enc.file_name()?.to_os_string();
        let sealed = self.hidden(enc).and_then(|(fingerprint, sealed)| {
            let group = self.groups.iter().find(|group| group.fingerprint == fingerprint)?;
            group.open_name(&name, &sealed)
        });
        sealed.or_else(|| is_random(&name).then(|| recall(enc)).flatten()).filter(|real| manifest::plain_name(real))
    }

    /// Says so if `enc` has a random name but no real one was found, so it's
    /// decrypted under the random one.
    pub fn note_if_unnamed(&mut self, enc: &Path) {
        if enc.file_name().is_some_and(is_random) && self.real_name(enc).is_none() {
            eprintln!(
                "note: {} has a random name, and its real name is in neither its folder's .encryptor file (for \
                 its key) nor the list in ~/.local/share/encryptor/filenames, so it keeps the random name.",
                safe_path(enc)
            );
        }
    }

    /// Where `enc` is decrypted to: its real name beside it, if it has one,
    /// or else its own name without `.enc`.
    pub fn output(&mut self, enc: &Path) -> PathBuf {
        match self.real_name(enc) {
            Some(real) => files::folder(enc).join(real),
            None => files::decrypted_path(enc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    #[test]
    fn names_files_with_16_random_bytes() {
        let a = random_name(Path::new("docs/report.pdf")).unwrap();
        let b = random_name(Path::new("docs/report.pdf")).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(Path::new("docs")));
        assert!(is_random(a.file_name().unwrap()), "{a:?}");
        assert!(!is_random(OsStr::new("report.pdf.enc")));
        assert!(!is_random(OsStr::new("9f2c41a0d3e8b7c6f1a25e0d4b8c3f7.enc")));
    }

    #[test]
    fn reads_back_a_list_and_finds_names_anywhere_in_it() {
        let mut list = List::default();
        list.add(OsStr::new("/a/docs"), OsStr::new("11.enc"), OsStr::new("one.txt"));
        list.add(OsStr::new("/b/docs"), OsStr::new("22.enc"), OsStr::new("two\ttabbed.txt"));
        list.add(OsStr::new("/a/docs"), OsStr::new("11.enc"), OsStr::new("again.txt"));
        let text = list.to_text();
        let read = List::parse(&text).unwrap();
        assert_eq!(read, list);
        assert_eq!(read.find(Some(OsStr::new("/a/docs")), OsStr::new("11.enc")), Some("again.txt".into()));
        // Found under another folder, as after the folder was moved.
        assert_eq!(read.find(Some(OsStr::new("/c/docs")), OsStr::new("22.enc")), Some("two\ttabbed.txt".into()));
        assert_eq!(read.find(None, OsStr::new("33.enc")), None);
        assert!(List::parse(b"encryptor-filenames 1\n/a\n  x.enc\t../up\n").is_none());
    }

    #[test]
    fn finds_a_hidden_name_with_its_group_key_only() {
        let dir = Scratch::new("names-namer");
        let enc = random_name(&dir.join("report.pdf")).unwrap();
        let group = GroupKey::of_key(&[5; KEY_LEN]);
        let entry = manifest::Entry::new(&enc, &group, Some(OsStr::new("report.pdf"))).unwrap();
        manifest::record(&[entry]);

        let mut namer = Namer::default();
        // Without the key (and nothing in the lists, as HOME isn't touched
        // here) the name stays hidden.
        namer.unlock(&enc, Unlock::Key(&[6; KEY_LEN])).unwrap();
        assert_eq!(namer.output(&enc), files::decrypted_path(&enc));
        namer.unlock(&enc, Unlock::Key(&[5; KEY_LEN])).unwrap();
        assert_eq!(namer.output(&enc), dir.join("report.pdf"));
    }
}
