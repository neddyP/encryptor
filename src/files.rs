//! Files: checking the one given, reading it back past the cache, buffers
//! for secrets, and writing output so a partial file never takes its place.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::term::{self, safe_path};
use crate::{protect, wipe};

const ENC_EXT: &str = "enc";

/// The size of the file `command` was given, if it's a regular file, or an
/// explanation of why it can't be used.
pub fn input_len(command: &str, path: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::File(explain::missing(command, path, &e)))?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(Error::File(explain::symlink(command, path)));
    }
    if kind.is_dir() {
        return Err(Error::File(match command {
            "encrypt" => explain::zip_instead(&[path.to_string_lossy().into_owned()]),
            _ => explain::decrypt_folder(path),
        }));
    }
    if !kind.is_file() {
        return Err(Error::File(explain::special(path, kind)));
    }
    Ok(meta.len())
}

/// Fails, explaining why, if `path` couldn't be created in its folder.
pub fn check_writable(path: &Path) -> Result<()> {
    let folder = folder(path);
    let folder = CString::new(folder.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: access only reads the NUL-terminated path.
    if unsafe { libc::access(folder.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        return Ok(());
    }
    Err(Error::File(explain::file(Action::Create, path, &io::Error::last_os_error())))
}

/// Whether two paths lead to the same existing file.
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// Opens a file just written and flushed, to read it back from the disk
/// rather than from the copy the system keeps in memory, which would match
/// what was written whether or not the disk holds it. On Linux its cached
/// pages, clean once flushed, are dropped; on macOS caching is turned off for
/// the reads, Apple's counterpart to direct I/O.
pub fn open_uncached(path: &Path) -> io::Result<File> {
    let file = open_no_follow(path)?;
    // SAFETY: plain calls on a descriptor that stays open throughout.
    #[cfg(target_os = "linux")]
    let failed = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) } != 0;
    #[cfg(target_os = "macos")]
    let failed = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1) } == -1;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let failed = false;
    if failed {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// A zeroed buffer for plaintext and other secrets: allocated at its final
/// size so it never reallocates and leaves copies behind, locked in RAM when
/// the limit allows, and wiped when dropped.
pub fn secret_buffer(len: u64) -> Result<Zeroizing<Vec<u8>>> {
    let size = usize::try_from(len).map_err(|_| explain::no_memory(len))?;
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(size).map_err(|_| explain::no_memory(len))?;
    buf.resize(size, 0);
    protect::lock(buf.as_ptr(), size);
    Ok(buf)
}

/// Reads a whole file, refusing symlinks, into a secret buffer.
pub fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let read_error = |e| Error::File(explain::file(Action::Read, path, &e));
    let mut file = open_no_follow(path).map_err(read_error)?;
    let len = file.metadata().map_err(read_error)?.len();
    let mut buf = secret_buffer(len)?;
    file.read_exact(&mut buf).map_err(read_error)?;
    Ok(buf)
}

pub fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(data).into())
}

/// The SHA-256 of a file just written, read back from the disk.
pub fn sha256_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let read_error = |e| Error::File(explain::file(Action::Read, path, &e));
    let mut file = open_uncached(path).map_err(read_error)?;
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

/// A file written under a temporary name in its folder and put in place by
/// `finish` once it is complete and flushed to disk, so a crash never leaves
/// a half-written file under the final name. Only the owner can read it, and
/// it is shredded, not just deleted, if dropped unfinished, since it may hold
/// plaintext.
pub struct PartFile {
    file: File,
    tmp: PathBuf,
    path: PathBuf,
    replace: bool,
    finished: bool,
}

/// What became of a file that `PartFile` replaced.
pub enum Replaced {
    Nothing,
    /// Overwritten with zeros, then deleted.
    Shredded,
    /// Deleted but not overwritten, since other names still lead to it.
    Unlinked,
}

impl PartFile {
    /// Starts writing `path`, which mustn't exist unless `replace` is set.
    pub fn create(path: &Path, replace: bool) -> Result<Self> {
        if !replace && path.exists() {
            return Err(Error::File(format!("{} already exists", safe_path(path))));
        }
        let tmp = with_suffix(path, &format!(".{}.part", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::File(explain::file(Action::Create, path, &e)))?;
        Ok(Self { file, tmp, path: path.to_path_buf(), replace, finished: false })
    }

    /// Flushes the file to disk and puts it in place, and makes that lasting
    /// by flushing the folder too. A file it replaces is swapped out in one
    /// step where the system can, so the name is never missing, and then
    /// shredded: it is often plaintext from an earlier decryption.
    pub fn finish(mut self) -> Result<Replaced> {
        let write_error = |e| Error::File(explain::file(Action::Write, &self.path, &e));
        self.file.sync_all().map_err(write_error)?;
        let replaced = if self.replace && swap(&self.tmp, &self.path).is_ok() {
            // The old file now has the temporary name.
            self.finished = true;
            dispose_of(&self.tmp)
        } else {
            let replaced = match self.replace {
                true => shred_in_place(&self.path),
                false => Replaced::Nothing,
            };
            fs::rename(&self.tmp, &self.path).map_err(write_error)?;
            self.finished = true;
            replaced
        };
        File::open(folder(&self.path)).and_then(|dir| dir.sync_all()).map_err(write_error)?;
        Ok(replaced)
    }
}

impl Write for PartFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A partial file can be large and take a while to overwrite, so say
        // what's happening rather than seem to hang after Ctrl-C.
        let size = self.file.metadata().map_or(0, |meta| meta.len());
        let mut progress = term::Progress::new("Shredding", size);
        if progress.shown() {
            eprintln!(
                "\nOverwriting the unfinished {} with zeros before deleting it, as it may hold plaintext.",
                safe_path(&self.tmp)
            );
        }
        let _ = wipe::shred_with_progress(&self.tmp, &mut |done| progress.update(done));
    }
}

/// Exchanges two names in one step, so neither is ever missing.
fn swap(a: &Path, b: &Path) -> io::Result<()> {
    let a = CString::new(a.as_os_str().as_bytes())?;
    let b = CString::new(b.as_os_str().as_bytes())?;
    // SAFETY: both paths are NUL-terminated and outlive the call.
    #[cfg(target_os = "linux")]
    let done = unsafe { libc::renameat2(libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), libc::RENAME_EXCHANGE) };
    #[cfg(target_os = "macos")]
    let done = unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let done = {
        let _ = (a, b);
        -1
    };
    if done == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Removes a replaced file, overwriting it first if this was its only name:
/// with other hard links to it, zeroing it would destroy what they show.
fn dispose_of(path: &Path) -> Replaced {
    let only_name = fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.nlink() == 1);
    if only_name && wipe::shred(path).is_ok() {
        return Replaced::Shredded;
    }
    let _ = fs::remove_file(path);
    Replaced::Unlinked
}

/// Overwrites a file about to be replaced, where it can't be swapped out
/// first, if this is its only name.
fn shred_in_place(path: &Path) -> Replaced {
    match fs::symlink_metadata(path) {
        Err(_) => Replaced::Nothing,
        Ok(meta) if meta.is_file() && meta.nlink() == 1 && wipe::zero(path).is_ok() => Replaced::Shredded,
        Ok(_) => Replaced::Unlinked,
    }
}

/// The folder a path is in, as given.
fn folder(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn encrypted_path(input: &Path) -> PathBuf {
    with_suffix(input, &format!(".{ENC_EXT}"))
}

pub fn decrypted_path(input: &Path) -> PathBuf {
    if input.extension().is_some_and(|ext| ext == ENC_EXT) {
        input.with_extension("")
    } else {
        with_suffix(input, ".dec")
    }
}

/// The file `command` works on: the one given on the command line, or else
/// one typed at a prompt.
pub fn file_path(command: &str, arg: Option<&str>) -> Result<PathBuf> {
    match arg {
        Some(arg) => Ok(PathBuf::from(arg)),
        None => {
            let raw = term::read_line(&format!("File to {command}: "))?;
            if raw.is_empty() {
                return Err(Error::Usage(explain::no_file_given(command)));
            }
            Ok(clean_path(&raw))
        }
    }
}

/// Tidies a typed or dragged-in path: strips surrounding quotes and expands a
/// leading `~/`, which the shell would normally do.
pub fn clean_path(raw: &str) -> PathBuf {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encryptor-files-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_encrypted_and_decrypted_files() {
        assert_eq!(encrypted_path(Path::new("a/report.pdf")), Path::new("a/report.pdf.enc"));
        assert_eq!(decrypted_path(Path::new("a/report.pdf.enc")), Path::new("a/report.pdf"));
        assert_eq!(decrypted_path(Path::new("notes")), Path::new("notes.dec"));
    }

    #[test]
    fn puts_a_finished_file_in_place() {
        let dir = scratch("finish");
        let path = dir.join("out");
        let mut part = PartFile::create(&path, false).unwrap_or_else(|_| panic!("create"));
        part.write_all(b"new").unwrap();
        assert!(!path.exists(), "visible before it was finished");
        assert!(matches!(part.finish(), Ok(Replaced::Nothing)));
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "the temporary file is gone");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shreds_the_file_it_replaces() {
        let dir = scratch("replace");
        let path = dir.join("out");
        fs::write(&path, b"old plaintext").unwrap();
        // Opened before the replacement, this still sees the old file.
        let old = File::open(&path).unwrap();

        let mut part = PartFile::create(&path, true).unwrap_or_else(|_| panic!("create"));
        part.write_all(b"new").unwrap();
        assert!(matches!(part.finish(), Ok(Replaced::Shredded)));
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let mut left = Vec::new();
        (&old).read_to_end(&mut left).unwrap();
        assert_eq!(left, vec![0; 13], "the old contents were overwritten");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn leaves_other_links_to_a_replaced_file_alone() {
        let dir = scratch("linked");
        let path = dir.join("out");
        fs::write(&path, b"shared").unwrap();
        fs::hard_link(&path, dir.join("backup")).unwrap();

        let mut part = PartFile::create(&path, true).unwrap_or_else(|_| panic!("create"));
        part.write_all(b"new").unwrap();
        assert!(matches!(part.finish(), Ok(Replaced::Unlinked)));
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read(dir.join("backup")).unwrap(), b"shared");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shreds_an_unfinished_file() {
        let dir = scratch("unfinished");
        let path = dir.join("out");
        let mut part = PartFile::create(&path, false).unwrap_or_else(|_| panic!("create"));
        part.write_all(b"partial plaintext").unwrap();
        let tmp = part.tmp.clone();
        let witness = dir.join("witness");
        fs::hard_link(&tmp, &witness).unwrap();
        drop(part);
        assert!(!tmp.exists() && !path.exists());
        assert_eq!(fs::read(&witness).unwrap(), vec![0; 17]);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a real disk drops pages; tmpfs holds files in the cache itself.
    #[cfg(target_os = "linux")]
    #[test]
    fn reads_back_past_the_page_cache() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("cache-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("written");
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        file.write_all(&vec![7u8; 1 << 20]).unwrap();
        file.sync_all().unwrap();
        let resident = |file: &File| {
            // SAFETY: maps the whole open file read-only and asks which pages
            // are in memory, into a vector of one byte per page.
            unsafe {
                let len = 1 << 20;
                let map = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0);
                assert_ne!(map, libc::MAP_FAILED);
                let mut pages = vec![0u8; len.div_ceil(4096)];
                libc::mincore(map, len, pages.as_mut_ptr().cast());
                libc::munmap(map, len);
                pages.iter().filter(|&&p| p & 1 == 1).count()
            }
        };
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: fills in a statfs for an open descriptor.
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) };
        let tmpfs = stat.f_type as i64 == libc::TMPFS_MAGIC as i64;

        let before = resident(&file);
        let reopened = open_uncached(&path).unwrap();
        let after = resident(&reopened);
        fs::remove_dir_all(&dir).unwrap();
        if !tmpfs {
            assert!(before > 0, "the written pages start out cached");
            assert_eq!(after, 0, "{after} pages still cached");
        }
    }
}
