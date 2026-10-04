//! Deleting files without leaving their contents or names behind, and
//! redacting keys from shell history files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The file being encrypted. It is opened once, refusing symlinks, and read
/// and overwritten through that same handle, so swapping its name for a link
/// to another file part way through can't redirect either step.
pub struct Original {
    file: File,
    dev: u64,
    ino: u64,
    writable: bool,
}

impl Original {
    pub fn open(path: &Path) -> io::Result<Self> {
        let open = |write| {
            OpenOptions::new()
                .read(true)
                .write(write)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
        };
        let (file, writable) = match open(true) {
            Ok(file) => (file, true),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => (open(false)?, false),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        Ok(Self { file, dev: meta.dev(), ino: meta.ino(), writable })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(buf)
    }

    /// Overwrites the contents with zeros through the open handle, then
    /// deletes the name, but only if it still refers to this same file.
    /// Describes what happened, for the report.
    pub fn destroy(mut self, path: &Path) -> String {
        let zeroed = self.writable && zero_fill(&mut self.file).is_ok();
        match remove_if_same(path, self.dev, self.ino) {
            Ok(()) if zeroed => "overwritten with zeros, name scrambled, then deleted".into(),
            Ok(()) => "name scrambled and deleted (read-only, so not overwritten)".into(),
            Err(e) => format!(
                "WARNING: not deleted, as {}. The encrypted copy is verified, so delete the original yourself",
                crate::explain::cause(crate::explain::Action::Delete, path, &e)
            ),
        }
    }
}

/// Overwrites a file this program created with zeros, then deletes it under a
/// scrambled name. Used for unused key files and partial or rejected output.
pub fn shred(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    zero_fill(&mut file)?;
    remove_if_same(path, meta.dev(), meta.ino())
}

/// Overwrites a file's contents with zeros in place and flushes them to disk.
fn zero_fill(file: &mut File) -> io::Result<()> {
    let zeros = vec![0u8; 1 << 16];
    let mut remaining = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    file.sync_all()
}

/// Deletes `path` if it is still the file identified by `dev` and `ino`. The
/// file is first renamed to random characters of the same length, so the
/// directory doesn't keep its original name either.
fn remove_if_same(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
    let same = |p: &Path| {
        fs::symlink_metadata(p).map(|m| m.is_file() && m.dev() == dev && m.ino() == ino)
    };
    let replaced = || io::Error::other("it was replaced by another file part way through");
    if !same(path)? {
        return Err(replaced());
    }
    let target = match scrambled_name(path) {
        Some(new) if fs::symlink_metadata(&new).is_err() && fs::rename(path, &new).is_ok() => new,
        _ => path.to_path_buf(),
    };
    if !same(&target)? {
        return Err(replaced());
    }
    fs::remove_file(&target)
}

fn scrambled_name(path: &Path) -> Option<PathBuf> {
    let len = path.file_name()?.len();
    let mut random = vec![0u8; len.div_ceil(2)];
    getrandom::fill(&mut random).ok()?;
    Some(path.with_file_name(&hex::encode(random)[..len]))
}

/// Shell history files that could hold a key typed or pasted into a command.
pub fn history_files() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/share")));
    let mut files: Vec<PathBuf> =
        std::env::var_os("HISTFILE").map(PathBuf::from).into_iter().collect();
    if let Some(home) = &home {
        for name in [".bash_history", ".zsh_history", ".zhistory", ".histfile", ".sh_history"] {
            files.push(home.join(name));
        }
    }
    if let Some(data) = data {
        files.push(data.join("fish/fish_history"));
    }
    files.sort();
    files.dedup();
    files
}

/// Replaces every copy of `key`'s hex form in the file (in either case) with
/// asterisks. The file keeps its length and structure, and the old characters
/// are overwritten where they are rather than left behind in freed disk
/// blocks. Returns how many copies were redacted; a missing file has none.
pub fn redact_key(path: &Path, key: &[u8; 32]) -> io::Result<usize> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let len = usize::try_from(file.metadata()?.len()).map_err(io::Error::other)?;
    let mut contents = Zeroizing::new(vec![0u8; len]);
    file.read_exact_at(&mut contents, 0)?;

    let mut hex = Zeroizing::new([0u8; 64]);
    hex::encode_to_slice(key, &mut hex[..]).expect("a 32-byte key is 64 hex characters");
    let mut found = 0;
    let mut i = 0;
    while i + hex.len() <= contents.len() {
        if contents[i..i + hex.len()].eq_ignore_ascii_case(&hex[..]) {
            file.write_all_at(&[b'*'; 64], i as u64)?;
            found += 1;
            i += hex.len();
        } else {
            i += 1;
        }
    }
    if found > 0 {
        file.sync_all()?;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aes256-wipe-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn destroy_zeroes_contents_and_removes_the_name() {
        let dir = scratch("destroy");
        let path = dir.join("secret.txt");
        fs::write(&path, b"top secret").unwrap();
        // A second link to the same file shows what happened to its contents.
        let witness = dir.join("witness");
        fs::hard_link(&path, &witness).unwrap();

        let status = Original::open(&path).unwrap().destroy(&path);
        assert!(status.starts_with("overwritten with zeros"), "{status}");
        assert!(!path.exists());
        assert_eq!(fs::read(&witness).unwrap(), vec![0u8; 10]);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "only the witness is left");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_to_open_a_symlink() {
        let dir = scratch("nofollow");
        fs::write(dir.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("target"), dir.join("link")).unwrap();
        assert!(Original::open(&dir.join("link")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn swapping_the_name_for_a_link_protects_the_target() {
        let dir = scratch("swap");
        let path = dir.join("secret.txt");
        let victim = dir.join("victim");
        fs::write(&path, b"secret").unwrap();
        fs::write(&victim, b"precious").unwrap();

        let original = Original::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        let status = original.destroy(&path);
        assert!(status.starts_with("WARNING: not deleted"), "{status}");
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shred_zeroes_then_removes() {
        let dir = scratch("shred");
        let path = dir.join("partial");
        fs::write(&path, b"plaintext").unwrap();
        let witness = dir.join("witness");
        fs::hard_link(&path, &witness).unwrap();
        shred(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&witness).unwrap(), vec![0u8; 9]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn redacts_keys_in_place_in_either_case() {
        let dir = scratch("history");
        let key = [0xabu8; 32];
        let lower = hex::encode(key);
        let upper = lower.to_uppercase();
        let path = dir.join(".bash_history");
        let history = format!(
            "ls\n#1700000000\nprintf '{lower}\\ny\\n' | decrypt a.enc\necho {upper}\ncd /\n"
        );
        fs::write(&path, &history).unwrap();

        assert_eq!(redact_key(&path, &key).unwrap(), 2);
        let after = fs::read_to_string(&path).unwrap();
        let stars = "*".repeat(64);
        assert_eq!(after.len(), history.len());
        let expected = format!(
            "ls\n#1700000000\nprintf '{stars}\\ny\\n' | decrypt a.enc\necho {stars}\ncd /\n"
        );
        assert_eq!(after, expected);
        assert_eq!(redact_key(&path, &key).unwrap(), 0);
        assert_eq!(redact_key(&dir.join("missing"), &key).unwrap(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}
