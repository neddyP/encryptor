//! Traces Linux desktops keep of files, removed for an original once it's
//! destroyed: thumbnails, which are small pictures of a file's contents made
//! when a file manager or file picker shows it, and the list of recently
//! used files. Both follow freedesktop.org specifications, which GNOME, KDE,
//! Xfce and others share, and find a file by its URI.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::wipe;

/// Removes the thumbnails and recently used entry of `path`, a file just
/// deleted, and describes what was done. None on macOS, which keeps neither
/// where this can reach them.
pub fn forget(path: &Path) -> Option<String> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let uris = uris(path);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let under_home = |var: &str, default: &str| {
        std::env::var_os(var).map(PathBuf::from).or_else(|| home.as_ref().map(|h| h.join(default)))
    };

    let mut thumbnails = 0;
    if let Some(cache) = under_home("XDG_CACHE_HOME", ".cache") {
        for file in thumbnail_files(&cache.join("thumbnails"), &uris) {
            if wipe::shred(&file).is_ok() {
                thumbnails += 1;
            }
        }
    }
    let recent = match under_home("XDG_DATA_HOME", ".local/share") {
        Some(data) => remove_recent(&data.join("recently-used.xbel"), &uris).unwrap_or(0),
        None => 0,
    };

    Some(match (thumbnails, recent) {
        (0, 0) => "no thumbnails or recently used entries found".into(),
        (n, 0) => format!("removed {}", plural(n, "thumbnail")),
        (0, n) => format!("removed {}", plural(n, "recently used entry")),
        (t, r) => format!("removed {} and {}", plural(t, "thumbnail"), plural(r, "recently used entry")),
    })
}

fn plural(n: usize, what: &str) -> String {
    match (n, what.strip_suffix('y')) {
        (1, _) => format!("1 {what}"),
        (_, Some(stem)) => format!("{n} {stem}ies"),
        _ => format!("{n} {what}s"),
    }
}

/// The URIs desktop software could know the file by: through the folder's
/// real path, and through the path as given if that differs, such as by way
/// of a symlinked folder.
fn uris(path: &Path) -> Vec<String> {
    let absolute = std::env::current_dir().map(|dir| dir.join(path)).unwrap_or_else(|_| path.to_path_buf());
    let mut paths = vec![absolute.clone()];
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
        if let Ok(real) = parent.canonicalize() {
            paths.insert(0, real.join(name));
        }
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

/// Removes the entries for any of `uris` from a recently-used.xbel file,
/// rewriting it in place, and returns how many there were.
fn remove_recent(path: &Path, uris: &[String]) -> io::Result<usize> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let mut contents = Zeroizing::new(vec![0u8; usize::try_from(len).map_err(io::Error::other)?]);
    file.read_exact_at(&mut contents, 0)?;
    let (kept, removed) = without_bookmarks(&contents, uris);
    if removed > 0 {
        wipe::rewrite(&file, len, &kept)?;
    }
    Ok(removed)
}

/// The XBEL text without the <bookmark> elements whose href is one of `uris`,
/// each taken out with the indent before it and the line break after it.
fn without_bookmarks(xbel: &[u8], uris: &[String]) -> (Zeroizing<Vec<u8>>, usize) {
    // The href is the URI as an XML attribute value, as GLib writes it.
    let starts: Vec<String> = uris
        .iter()
        .map(|uri| format!("<bookmark href=\"{}\"", uri.replace('&', "&amp;").replace('\'', "&#39;")))
        .collect();
    let end = b"</bookmark>";
    let mut kept = Zeroizing::new(Vec::with_capacity(xbel.len()));
    let mut removed = 0;
    let mut at = 0;
    while at < xbel.len() {
        let found = starts.iter().filter_map(|start| find(&xbel[at..], start.as_bytes())).min();
        let Some(offset) = found else { break };
        let start = at + offset;
        let Some(close) = find(&xbel[start..], end) else { break };
        let mut from = start;
        while from > at && matches!(xbel[from - 1], b' ' | b'\t') {
            from -= 1;
        }
        let mut to = start + close + end.len();
        if xbel.get(to) == Some(&b'\n') {
            to += 1;
        }
        kept.extend_from_slice(&xbel[at..from]);
        removed += 1;
        at = to;
    }
    kept.extend_from_slice(&xbel[at.min(xbel.len())..]);
    (kept, removed)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn makes_uris_as_glib_does() {
        assert_eq!(file_uri(Path::new("/home/me/report.pdf")), "file:///home/me/report.pdf");
        assert_eq!(file_uri(Path::new("/tmp/a b#c%d.txt")), "file:///tmp/a%20b%23c%25d.txt");
        assert_eq!(file_uri(Path::new("/tmp/Tom & Jerry's (1).png")), "file:///tmp/Tom%20&%20Jerry's%20(1).png");
        assert_eq!(file_uri(Path::new("/tmp/café")), "file:///tmp/caf%C3%A9");
    }

    #[test]
    fn removes_matching_bookmarks_only() {
        let uri = "file:///home/me/Tom%20&%20Jerry's.pdf".to_string();
        let xbel = "<?xml version=\"1.0\"?>\n<xbel version=\"1.0\">\n  \
                    <bookmark href=\"file:///home/me/other.pdf\" added=\"x\">\n    <info/>\n  </bookmark>\n  \
                    <bookmark href=\"file:///home/me/Tom%20&amp;%20Jerry&#39;s.pdf\" added=\"x\">\n    <info>\n      \
                    <bookmark:applications/>\n    </info>\n  </bookmark>\n</xbel>\n";
        let (kept, removed) = without_bookmarks(xbel.as_bytes(), &[uri]);
        assert_eq!(removed, 1);
        assert_eq!(
            String::from_utf8(kept.to_vec()).unwrap(),
            "<?xml version=\"1.0\"?>\n<xbel version=\"1.0\">\n  \
             <bookmark href=\"file:///home/me/other.pdf\" added=\"x\">\n    <info/>\n  </bookmark>\n</xbel>\n"
        );
    }

    #[test]
    fn forgets_thumbnails_and_recent_entries() {
        let dir = std::env::temp_dir().join(format!("encryptor-desktop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (cache, data) = (dir.join("cache"), dir.join("data"));
        let path = dir.join("photo.jpg");
        let uri = file_uri(&path);
        let name = format!("{}.png", hex::encode(Md5::digest(uri.as_bytes())));
        for folder in ["thumbnails/large", "thumbnails/fail/gnome-thumbnail-factory"] {
            fs::create_dir_all(cache.join(folder)).unwrap();
            fs::write(cache.join(folder).join(&name), b"png").unwrap();
        }
        fs::write(cache.join("thumbnails/large/other.png"), b"png").unwrap();
        fs::create_dir_all(&data).unwrap();
        let xbel = data.join("recently-used.xbel");
        fs::write(&xbel, format!("<xbel>\n  <bookmark href=\"{uri}\">\n  </bookmark>\n</xbel>\n")).unwrap();

        let thumbnails = thumbnail_files(&cache.join("thumbnails"), &uris(&path));
        assert_eq!(thumbnails.len(), 2);
        assert_eq!(remove_recent(&xbel, &uris(&path)).unwrap(), 1);
        assert_eq!(fs::read_to_string(&xbel).unwrap(), "<xbel>\n</xbel>\n");
        assert_eq!(remove_recent(&data.join("missing.xbel"), &uris(&path)).unwrap(), 0);
        assert_eq!(plural(2, "recently used entry"), "2 recently used entries");
        fs::remove_dir_all(&dir).unwrap();
    }
}
