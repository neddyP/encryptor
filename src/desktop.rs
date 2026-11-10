//! Thumbnails Linux desktops make of files, removed for an original once it's
//! destroyed: small pictures of a file's contents, made when a file manager
//! or file picker shows it, which would otherwise outlive the original. They
//! follow a freedesktop.org specification, which GNOME, KDE, Xfce and others
//! share, and are found by the file's URI.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use md5::{Digest, Md5};

use crate::wipe;

/// Removes the thumbnails of `path`, a file just deleted, and says how many
/// there were. None on macOS, which keeps none where this can reach them.
pub fn remove_thumbnails(path: &Path) -> Option<usize> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    let removed = thumbnail_files(&cache.join("thumbnails"), &uris(path))
        .iter()
        .filter(|file| wipe::shred(file).is_ok())
        .count();
    Some(removed)
}

/// The URIs desktop software could know the file by: through the folder's
/// real path, and through the path as given if that differs, such as by way
/// of a symlinked folder.
fn uris(path: &Path) -> Vec<String> {
    let absolute = std::env::current_dir().map(|dir| dir.join(path)).unwrap_or_else(|_| path.to_path_buf());
    let mut paths = vec![absolute.clone()];
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name())
        && let Ok(real) = parent.canonicalize()
    {
        paths.insert(0, real.join(name));
    }
    paths.dedup();
    paths.iter().map(|path| file_uri(path)).collect()
}

/// A path as a file:// URI, escaped exactly as GLib's g_filename_to_uri does,
/// since the names of thumbnails are the MD5 of that text.
fn file_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()/&=:@+$,".contains(&b) {
            uri.push(b as char);
        } else {
            uri.push_str(&format!("%{b:02X}"));
        }
    }
    uri
}

/// The thumbnails that exist for any of `uris`, in every size, and the
/// markers left where making one failed.
fn thumbnail_files(dir: &Path, uris: &[String]) -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = ["normal", "large", "x-large", "xx-large"].iter().map(|s| dir.join(s)).collect();
    if let Ok(entries) = std::fs::read_dir(dir.join("fail")) {
        folders.extend(entries.flatten().map(|entry| entry.path()));
    }
    let names: Vec<String> = uris.iter().map(|uri| format!("{}.png", hex::encode(Md5::digest(uri.as_bytes())))).collect();
    folders
        .iter()
        .flat_map(|folder| names.iter().map(move |name| folder.join(name)))
        .filter(|file| file.symlink_metadata().is_ok_and(|meta| meta.is_file()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testing::Scratch;

    #[test]
    fn makes_uris_as_glib_does() {
        assert_eq!(file_uri(Path::new("/home/me/report.pdf")), "file:///home/me/report.pdf");
        assert_eq!(file_uri(Path::new("/tmp/a b#c%d.txt")), "file:///tmp/a%20b%23c%25d.txt");
        assert_eq!(file_uri(Path::new("/tmp/Tom & Jerry's (1).png")), "file:///tmp/Tom%20&%20Jerry's%20(1).png");
        assert_eq!(file_uri(Path::new("/tmp/café")), "file:///tmp/caf%C3%A9");
    }

    #[test]
    fn finds_thumbnails_in_every_size() {
        let dir = Scratch::new("desktop");
        let cache = dir.join("cache");
        let path = dir.join("photo.jpg");
        let name = format!("{}.png", hex::encode(Md5::digest(file_uri(&path).as_bytes())));
        for folder in ["thumbnails/large", "thumbnails/fail/gnome-thumbnail-factory"] {
            fs::create_dir_all(cache.join(folder)).unwrap();
            fs::write(cache.join(folder).join(&name), b"png").unwrap();
        }
        fs::write(cache.join("thumbnails/large/other.png"), b"png").unwrap();

        assert_eq!(thumbnail_files(&cache.join("thumbnails"), &uris(&path)).len(), 2);
    }
}
