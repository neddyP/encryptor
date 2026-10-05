//! Setting the last-read times of encryptor's own files back to when they were
//! installed, at the end of every run. Starting the program reads them: its
//! binary, and when it's installed with npm, the package's launcher, the
//! command's link and the Node.js that runs the launcher. Left alone, their
//! last-read times would show when it last ran. Setting them back updates
//! their change times (ctime) instead, which no program can set, so only
//! files read since they last changed are set back. Where the disk doesn't
//! record reads (mounted with `noatime`), nothing is touched.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

/// Set by the npm package's launcher: the Node.js that ran it, and the
/// command it was started as, which is usually a link.
const NODE_VAR: &str = "ENCRYPTOR_NODE";
const LAUNCHED_AS_VAR: &str = "ENCRYPTOR_LAUNCHED_AS";

/// Sets the last-read time of each of the program's files back to when the
/// file was created. Files it may not change, such as a Node.js owned by root,
/// are left as they are.
pub fn reset() {
    for (path, follow) in files() {
        set_back(&path, follow);
    }
}

/// The program's files, each with whether to follow it if it's a link.
fn files() -> Vec<(PathBuf, bool)> {
    let Ok(exe) = std::env::current_exe().and_then(fs::canonicalize) else { return Vec::new() };
    let mut files = vec![(exe.clone(), true)];
    // Installed with npm, the binary is the package's vendor/<platform>/encryptor.
    let package = exe.parent().and_then(Path::parent).and_then(Path::parent).filter(|dir| is_package(dir));
    let Some(package) = package else { return files };

    files.push((package.join("package.json"), true));
    for folder in ["bin", "lib"] {
        let folder = package.join(folder);
        if let Ok(entries) = fs::read_dir(&folder) {
            files.extend(entries.flatten().map(|entry| (entry.path(), true)));
        }
        // Listing it just now read the folder too.
        files.push((folder, true));
    }
    // The link the command was run through, such as ~/.local/bin/encrypt,
    // when it leads into this package.
    if let Some(link) = std::env::var_os(LAUNCHED_AS_VAR).map(PathBuf::from)
        && fs::canonicalize(&link).is_ok_and(|real| real.starts_with(package))
    {
        files.push((link, false));
    }
    if let Some(node) = std::env::var_os(NODE_VAR).map(PathBuf::from)
        && node.file_name().is_some_and(|name| name.as_bytes().starts_with(b"node"))
    {
        files.push((node, true));
    }
    files
}

/// Whether `dir` is this program's npm package.
fn is_package(dir: &Path) -> bool {
    fs::read_to_string(dir.join("package.json")).is_ok_and(|json| json.contains("\"@neddyp/encryptor\""))
}

/// Sets the last-read time of `path` to when it was created, or if the system
/// doesn't keep that, last modified, leaving its modified time alone. Only a
/// file read since it last changed is set back: otherwise its last-read time
/// shows nothing new, as on disks mounted with `noatime`, and setting it would
/// only stamp its change time with the run.
fn set_back(path: &Path, follow: bool) {
    let metadata = if follow { fs::metadata(path) } else { fs::symlink_metadata(path) };
    let Ok(metadata) = metadata else { return };
    let (Ok(secs), Ok(nanos)) = (u64::try_from(metadata.ctime()), u32::try_from(metadata.ctime_nsec())) else { return };
    let changed = UNIX_EPOCH + Duration::new(secs, nanos);
    if !metadata.accessed().is_ok_and(|read| read > changed) {
        return;
    }
    let Ok(when) = metadata.created().or_else(|_| metadata.modified()) else { return };
    let Ok(since) = when.duration_since(UNIX_EPOCH) else { return };
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else { return };
    let Ok(secs) = libc::time_t::try_from(since.as_secs()) else { return };
    let times = [
        libc::timespec { tv_sec: secs, tv_nsec: libc::c_long::from(since.subsec_nanos()) },
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
    ];
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    // SAFETY: a valid C path and two timespecs, as utimensat takes.
    unsafe {
        libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_the_last_read_time_back_and_keeps_the_modified_time() {
        let dir = std::env::temp_dir().join(format!("encryptor-timestamps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("encryptor");
        fs::write(&file, b"x").unwrap();
        let before = fs::metadata(&file).unwrap();
        // Read later, as running the program would.
        std::thread::sleep(Duration::from_millis(20));
        let later = libc::timespec { tv_sec: before.mtime() + 3600, tv_nsec: 0 };
        let keep = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT };
        let c = CString::new(file.as_os_str().as_bytes()).unwrap();
        // SAFETY: as in set_back.
        unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [later, keep].as_ptr(), 0) };
        assert_eq!(fs::metadata(&file).unwrap().atime(), before.mtime() + 3600);

        set_back(&file, true);
        let after = fs::metadata(&file).unwrap();
        let created = after.created().or_else(|_| after.modified()).unwrap();
        assert_eq!(after.accessed().unwrap(), created, "back to when it was made");
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.mtime_nsec(), before.mtime_nsec());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_a_file_not_read_since_alone() {
        let dir = std::env::temp_dir().join(format!("encryptor-unread-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("encryptor");
        fs::write(&file, b"x").unwrap();
        let before = fs::metadata(&file).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        set_back(&file, true);
        let after = fs::metadata(&file).unwrap();
        assert_eq!((after.ctime(), after.ctime_nsec()), (before.ctime(), before.ctime_nsec()), "change time untouched");
        assert_eq!(after.accessed().unwrap(), before.accessed().unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn knows_its_own_package() {
        let dir = std::env::temp_dir().join(format!("encryptor-package-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), b"{\n  \"name\": \"@neddyp/encryptor\",\n}").unwrap();
        assert!(is_package(&dir));
        fs::write(dir.join("package.json"), b"{\n  \"name\": \"something-else\",\n}").unwrap();
        assert!(!is_package(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
