//! Deleting files without leaving their contents or names behind, and
//! rewriting files in place so removed parts don't linger either.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::explain::{self, Action};

/// The file being encrypted. It is opened once, refusing symlinks, and read
/// and overwritten through that same handle, so swapping its name for a link
/// to another file part way through can't redirect either step.
pub struct Original {
    file: File,
    dev: u64,
    ino: u64,
}

impl Original {
    /// Opens the file, for overwriting too unless it's to be kept. It must
    /// then be its only name, since zeroing it would leave the other names as
    /// files of zeros, and deleting it would leave them with the contents.
    pub fn open(path: &Path, overwrite: bool) -> Result<Self> {
        let read_error = |e| Error::File(explain::file(Action::Read, path, &e));
        let file = open(path, false).map_err(read_error)?;
        let meta = file.metadata().map_err(read_error)?;
        if !meta.is_file() {
            return Err(read_error(io::Error::other("not a regular file")));
        }
        let (dev, ino) = (meta.dev(), meta.ino());
        if !overwrite {
            return Ok(Self { file, dev, ino });
        }
        if meta.nlink() > 1 {
            return Err(Error::File(explain::other_names(path, meta.nlink() - 1)));
        }
        let writable = match open(path, true) {
            Ok(writable) => writable,
            // Its owner can always allow writing, so a file they've made
            // read-only is allowed it for as long as it takes to open it.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied && owns(&meta) => {
                let mode = meta.permissions().mode() & 0o7777;
                set_mode(&file, mode | 0o200).map_err(|e| Error::File(explain::cant_overwrite(path, &e)))?;
                let reopened = open(path, true);
                let restored = set_mode(&file, mode);
                let writable = reopened.map_err(|e| Error::File(explain::cant_overwrite(path, &e)))?;
                restored.map_err(|e| Error::File(explain::cant_overwrite(path, &e)))?;
                writable
            }
            Err(e) => return Err(Error::File(explain::cant_overwrite(path, &e))),
        };
        let same = writable.metadata().is_ok_and(|m| m.dev() == dev && m.ino() == ino);
        if !same {
            return Err(Error::File(explain::cant_overwrite(
                path,
                &io::Error::other("it was replaced by another file part way through"),
            )));
        }
        Ok(Self { file: writable, dev, ino })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// The open file, ready to be read from the start.
    pub fn reader(&mut self) -> io::Result<&File> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(&self.file)
    }

    /// Overwrites the contents with zeros through the open handle, then
    /// deletes the name, but only if it still refers to this same file.
    /// Describes what happened, for the report: `Ok` once it's deleted.
    pub fn destroy(mut self, path: &Path) -> std::result::Result<String, String> {
        let size = self.file.metadata().map_or(0, |meta| meta.len());
        let mut progress = crate::term::Progress::new("Shredding the original", size);
        let zeroed = zero_fill(&mut self.file, &mut |done| progress.update(done));
        drop(progress);
        match remove_if_same(path, self.dev, self.ino) {
            Ok(()) if zeroed.is_ok() => Ok("overwritten with zeros, name scrambled, then deleted".into()),
            Ok(()) => Ok(format!(
                "WARNING: deleted, but overwriting it failed ({}), so its contents may remain on the disk",
                zeroed.err().map(|e| e.to_string()).unwrap_or_default()
            )),
            Err(e) => Err(format!(
                "WARNING: not deleted, as {}. The encrypted copy is verified, so delete the original yourself",
                explain::cause(Action::Delete, path, &e)
            )),
        }
    }
}

fn open(path: &Path, write: bool) -> io::Result<File> {
    OpenOptions::new().read(true).write(write).custom_flags(libc::O_NOFOLLOW).open(path)
}

fn owns(meta: &fs::Metadata) -> bool {
    // SAFETY: geteuid has no arguments and can't fail.
    meta.uid() == unsafe { libc::geteuid() }
}

fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    // SAFETY: a plain call on a descriptor that stays open throughout.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Replaces the first `old_len` bytes of a file with `contents`, which is no
/// longer, in place. The bytes left over are overwritten with zeros and
/// flushed to disk before the file is cut short, so what was removed isn't
/// left behind in freed disk blocks. Anything appended after `old_len` was
/// read, as by a shell saving its history meanwhile, is kept after `contents`.
pub fn rewrite(file: &File, old_len: u64, contents: &[u8]) -> io::Result<()> {
    let now = file.metadata()?.len();
    let appended_len = usize::try_from(now.saturating_sub(old_len)).map_err(io::Error::other)?;
    let mut appended = Zeroizing::new(vec![0u8; appended_len]);
    file.read_exact_at(&mut appended, old_len)?;
    file.write_all_at(contents, 0)?;
    file.write_all_at(&appended, contents.len() as u64)?;
    let new_len = (contents.len() + appended.len()) as u64;
    let zeros = [0u8; 1 << 12];
    let mut at = new_len;
    while at < now {
        let n = (now - at).min(zeros.len() as u64) as usize;
        file.write_all_at(&zeros[..n], at)?;
        at += n as u64;
    }
    file.sync_all()?;
    file.set_len(new_len)?;
    file.sync_all()
}

/// Overwrites a file this program created with zeros, then deletes it under a
/// scrambled name. Used for unused key files and partial or rejected output.
pub fn shred(path: &Path) -> io::Result<()> {
    shred_with_progress(path, &mut |_| {})
}

/// `shred`, telling `progress` how many bytes have been overwritten.
pub fn shred_with_progress(path: &Path, progress: &mut impl FnMut(u64)) -> io::Result<()> {
    let (mut file, meta) = open_for_overwrite(path)?;
    zero_fill(&mut file, progress)?;
    remove_if_same(path, meta.dev(), meta.ino())
}

/// Overwrites a file with zeros but leaves it in place, for a file about to
/// be replaced.
pub fn zero(path: &Path) -> io::Result<()> {
    zero_fill(&mut open_for_overwrite(path)?.0, &mut |_| {})
}

fn open_for_overwrite(path: &Path) -> io::Result<(File, fs::Metadata)> {
    let file = OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok((file, meta))
}

/// Overwrites a file's contents with zeros in place and flushes them to disk.
fn zero_fill(file: &mut File, progress: &mut impl FnMut(u64)) -> io::Result<()> {
    let zeros = vec![0u8; 1 << 16];
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut done = 0;
    while done < len {
        let n = (len - done).min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        done += n as u64;
        progress(done);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encryptor-wipe-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn destroy_zeroes_contents_and_removes_the_name() {
        let dir = scratch("destroy");
        let path = dir.join("secret.txt");
        fs::write(&path, b"top secret").unwrap();
        let original = Original::open(&path, true).unwrap();
        // A second name for the same file, made after opening, shows what
        // happened to its contents.
        let witness = dir.join("witness");
        fs::hard_link(&path, &witness).unwrap();

        let status = original.destroy(&path).unwrap();
        assert!(status.starts_with("overwritten with zeros"), "{status}");
        assert!(!path.exists());
        assert_eq!(fs::read(&witness).unwrap(), vec![0u8; 10]);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "only the witness is left");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_a_file_with_other_names() {
        let dir = scratch("links");
        let path = dir.join("secret.txt");
        fs::write(&path, b"top secret").unwrap();
        fs::hard_link(&path, dir.join("other")).unwrap();
        let refused = Original::open(&path, true).err().unwrap().to_string();
        assert!(refused.contains("has 1 other name"), "{refused}");
        assert!(Original::open(&path, false).is_ok(), "it can still be read to keep");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overwrites_a_read_only_file_and_leaves_its_permissions() {
        let dir = scratch("read-only");
        let path = dir.join("secret.txt");
        fs::write(&path, b"top secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let original = Original::open(&path, true).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o444);

        // A second name, made after opening, shows the contents were zeroed.
        let witness = dir.join("witness");
        fs::hard_link(&path, &witness).unwrap();
        let status = original.destroy(&path).unwrap();
        assert!(status.starts_with("overwritten with zeros"), "{status}");
        assert_eq!(fs::read(&witness).unwrap(), vec![0u8; 10]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rewrites_in_place_keeping_what_was_appended() {
        let dir = scratch("rewrite");
        let path = dir.join("history");
        fs::write(&path, b"keep\nremove\nkeep too\n").unwrap();
        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        // Something appends after the contents were read, at 21 bytes.
        OpenOptions::new().append(true).open(&path).unwrap().write_all(b"new\n").unwrap();
        rewrite(&file, 21, b"keep\nkeep too\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"keep\nkeep too\nnew\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_to_open_a_symlink() {
        let dir = scratch("nofollow");
        fs::write(dir.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("target"), dir.join("link")).unwrap();
        assert!(Original::open(&dir.join("link"), false).is_err());
        assert!(Original::open(&dir.join("link"), true).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn swapping_the_name_for_a_link_protects_the_target() {
        let dir = scratch("swap");
        let path = dir.join("secret.txt");
        let victim = dir.join("victim");
        fs::write(&path, b"secret").unwrap();
        fs::write(&victim, b"precious").unwrap();

        let original = Original::open(&path, true).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        let status = original.destroy(&path).unwrap_err();
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
}
