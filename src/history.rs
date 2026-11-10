//! Shell history: removing every entry that holds a key or passphrase from
//! bash, zsh and fish history files, including the history macOS's Terminal
//! keeps for each window, in case one was typed or pasted into a command.
//! Each file is rewritten in place and the bytes left over are zeroed before
//! it is cut short, so removed entries don't linger in freed disk blocks.
//!
//! A shell keeps its own session's history in memory and writes it out when it
//! exits, after this program has finished, so a key typed into the command
//! that ran it is only removed by a later run, unless the shell was told not
//! to save it (with bash's HISTCONTROL=ignorespace, zsh's HIST_IGNORE_SPACE,
//! or in fish, by starting the command with a space).

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::term::safe_path;
use crate::wipe;

/// Folders where macOS's Terminal keeps a history file for each window, as
/// bash and zsh are set up there (/etc/bashrc_Apple_Terminal and
/// /etc/zshrc_Apple_Terminal): `<window>.history`, and `<window>.historynew`
/// while a window is open.
const SESSION_FOLDERS: [&str; 2] = [".bash_sessions", ".zsh_sessions"];

/// Shell history files that could hold a key typed or pasted into a command.
pub fn files() -> Vec<PathBuf> {
    let var = |name| std::env::var_os(name).map(PathBuf::from);
    history_files(var("HOME"), var("XDG_DATA_HOME"), var("ZDOTDIR"), var("HISTFILE"))
}

fn history_files(
    home: Option<PathBuf>,
    data: Option<PathBuf>,
    zdotdir: Option<PathBuf>,
    histfile: Option<PathBuf>,
) -> Vec<PathBuf> {
    let data = data.or_else(|| home.as_ref().map(|h| h.join(".local/share")));
    let mut files: Vec<PathBuf> = histfile.into_iter().collect();
    if let Some(home) = &home {
        for name in [".bash_history", ".zsh_history", ".zhistory", ".histfile", ".sh_history"] {
            files.push(home.join(name));
        }
        let zsh_home = zdotdir.as_ref().unwrap_or(home);
        for folder in [home.join(SESSION_FOLDERS[0]), zsh_home.join(SESSION_FOLDERS[1])] {
            let Ok(entries) = fs::read_dir(&folder) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "history" || ext == "historynew") {
                    files.push(path);
                }
            }
        }
    }
    if let Some(data) = data {
        files.push(data.join("fish/fish_history"));
    }
    files.sort();
    files.dedup();
    files
}

/// The files cleaned, for the report, with Terminal's per-window files counted
/// by folder rather than named one by one.
fn describe(cleaned: &[PathBuf], shown: impl Fn(&Path) -> String) -> Vec<String> {
    let mut names = Vec::new();
    let mut folders: Vec<(&Path, usize)> = Vec::new();
    for path in cleaned {
        let folder = path.parent().filter(|dir| {
            dir.file_name().is_some_and(|name| SESSION_FOLDERS.iter().any(|folder| name == *folder))
        });
        match folder {
            Some(dir) => match folders.iter_mut().find(|(seen, _)| *seen == dir) {
                Some((_, count)) => *count += 1,
                None => folders.push((dir, 1)),
            },
            None => names.push(shown(path)),
        }
    }
    for (dir, count) in folders {
        let files = if count == 1 { "1 file".to_string() } else { format!("{count} files") };
        names.push(format!("{}/ ({files})", shown(dir)));
    }
    names
}

/// A secret that entries holding it are removed for, in case it was ever
/// typed or pasted into a command.
pub enum Secret<'a> {
    /// Found as its 64 hex characters, in either case.
    Key(&'a [u8; KEY_LEN]),
    /// Found exactly as typed.
    Passphrase(&'a [u8]),
}

/// Removes every entry holding `secret` from each shell history file, and
/// describes what was done.
pub fn clean(secret: Secret) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let shown = |path: &Path| match home.as_deref().and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", safe_path(rest)),
        None => safe_path(path),
    };
    let mut hex = Zeroizing::new([0u8; 2 * KEY_LEN]);
    let (needle, what) = match secret {
        Secret::Key(key) => {
            hex::encode_to_slice(key, &mut hex[..]).expect("a 32-byte key is 64 hex characters");
            (Needle { bytes: &hex[..], any_case: true }, "the key")
        }
        Secret::Passphrase(passphrase) => (Needle { bytes: passphrase, any_case: false }, "the passphrase"),
    };

    let mut total = 0;
    let mut cleaned = Vec::new();
    let mut unreadable = Vec::new();
    for path in files() {
        match clean_file(&path, &needle) {
            Ok(0) => {}
            Ok(removed) => {
                total += removed;
                cleaned.push(path);
            }
            Err(e) => unreadable.push(format!("{} ({e})", shown(&path))),
        }
    }
    let mut status = match total {
        0 => format!("no entries held {what}"),
        n => format!("removed {} holding {what}", entries(n)),
    };
    if !cleaned.is_empty() {
        status.push_str(&format!(", from {}", describe(&cleaned, shown).join(", ")));
    }
    if !unreadable.is_empty() {
        status.push_str(&format!("; could not check {}", unreadable.join(", ")));
    }
    status
}

fn entries(n: usize) -> String {
    if n == 1 { "1 entry".into() } else { format!("{n} entries") }
}

/// What entries are removed for holding.
struct Needle<'a> {
    bytes: &'a [u8],
    any_case: bool,
}

impl Needle<'_> {
    fn in_entry(&self, entry: &[u8]) -> bool {
        let found = |w: &[u8]| if self.any_case { w.eq_ignore_ascii_case(self.bytes) } else { w == self.bytes };
        !self.bytes.is_empty() && entry.windows(self.bytes.len()).any(found)
    }
}

/// Removes the entries holding `needle` from one history file, and returns
/// how many there were. A missing file has none.
fn clean_file(path: &Path, needle: &Needle) -> io::Result<usize> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let mut contents = Zeroizing::new(vec![0u8; usize::try_from(len).map_err(io::Error::other)?]);
    file.read_exact_at(&mut contents, 0)?;

    let fish = path.file_name().is_some_and(|name| name == "fish_history");
    let mut kept = Zeroizing::new(Vec::with_capacity(contents.len()));
    let mut removed = 0;
    for entry in split_entries(&contents, fish) {
        if needle.in_entry(entry) {
            removed += 1;
        } else {
            kept.extend_from_slice(entry);
        }
    }
    if removed > 0 {
        wipe::rewrite(&file, len, &kept)?;
    }
    Ok(removed)
}

/// Splits a history file into its entries, each with its line endings, so
/// that joining them gives back the file. In fish's format an entry is a
/// `- cmd:` line and the indented lines after it. Otherwise it's one line,
/// with the `#<time>` line bash writes before it when timestamps are on, and
/// the lines a trailing backslash joins on, as zsh writes multi-line commands.
fn split_entries(contents: &[u8], fish: bool) -> Vec<&[u8]> {
    let lines: Vec<&[u8]> = contents.split_inclusive(|&b| b == b'\n').collect();
    let mut entries = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        i += 1;
        if fish {
            while i < lines.len() && !lines[i].starts_with(b"- cmd:") {
                i += 1;
            }
        } else {
            let is_time = |line: &[u8]| {
                let line = line.trim_ascii_end();
                line.len() > 1 && line[0] == b'#' && line[1..].iter().all(u8::is_ascii_digit)
            };
            if is_time(lines[start]) && i < lines.len() {
                i += 1;
            }
            while i < lines.len() && lines[i - 1].trim_ascii_end().ends_with(b"\\") {
                i += 1;
            }
        }
        let from = lines[..start].iter().map(|l| l.len()).sum::<usize>();
        let to = from + lines[start..i].iter().map(|l| l.len()).sum::<usize>();
        entries.push(&contents[from..to]);
    }
    entries
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testing::Scratch;

    #[test]
    fn includes_terminal_window_history_on_macos() {
        let home = Scratch::new("history-sessions");
        let bash = home.join(".bash_sessions");
        let zdot = home.join("zdot");
        let zsh = zdot.join(".zsh_sessions");
        for dir in [&bash, &zsh] {
            fs::create_dir_all(dir).unwrap();
        }
        for file in ["A.history", "A.historynew", "A.session", "_expiration_check_timestamp"] {
            fs::write(bash.join(file), b"").unwrap();
        }
        fs::write(zsh.join("B.history"), b"").unwrap();
        fs::write(home.join(".zsh_sessions"), b"").unwrap();

        let files = history_files(Some(home.to_path_buf()), None, Some(zdot), None);
        assert!(files.contains(&bash.join("A.history")));
        assert!(files.contains(&bash.join("A.historynew")));
        assert!(files.contains(&zsh.join("B.history")), "zsh's folder follows ZDOTDIR");
        assert!(!files.iter().any(|f| f.ends_with("A.session") || f.ends_with("_expiration_check_timestamp")));
        assert!(files.contains(&home.join(".bash_history")));
    }

    #[test]
    fn counts_window_history_files_by_folder() {
        let cleaned = [
            PathBuf::from("/h/.bash_history"),
            PathBuf::from("/h/.bash_sessions/A.history"),
            PathBuf::from("/h/.bash_sessions/B.history"),
            PathBuf::from("/h/.zsh_sessions/C.history"),
        ];
        let shown = |p: &Path| p.to_string_lossy().replace("/h/", "~/");
        assert_eq!(
            describe(&cleaned, shown),
            ["~/.bash_history", "~/.bash_sessions/ (2 files)", "~/.zsh_sessions/ (1 file)"]
        );
    }

    /// A needle for the passphrase "hunter2 hunter2".
    fn phrase() -> Needle<'static> {
        Needle { bytes: b"hunter2 hunter2", any_case: false }
    }

    #[test]
    fn cleans_a_terminal_window_history_file() {
        let window = Scratch::new("history-window");
        let dir = window.join(".bash_sessions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("A.history");
        fs::write(&path, b"ls\necho 'hunter2 hunter2'\ncd ~\n").unwrap();
        assert_eq!(clean_file(&path, &phrase()).unwrap(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"ls\ncd ~\n");
    }

    #[test]
    fn splits_entries_in_each_format() {
        let bash = b"ls\n#1700000000\nencrypt a\n#1700000001\ncd /\n";
        assert_eq!(split_entries(bash, false), [&b"ls\n"[..], b"#1700000000\nencrypt a\n", b"#1700000001\ncd /\n"]);

        let zsh = b": 1700000000:0;ls\n: 1700000001:2;for f in *; do\\\nencrypt $f\\\ndone\n";
        let entries = split_entries(zsh, false);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1], &zsh[18..]);

        let fish = b"- cmd: ls\n  when: 1700000000\n- cmd: encrypt a\n  when: 1700000001\n  paths:\n    - a\n";
        let entries = split_entries(fish, true);
        assert_eq!(entries, [&b"- cmd: ls\n  when: 1700000000\n"[..], &fish[29..]]);
    }

    #[test]
    fn removes_whole_entries_holding_the_key_only() {
        let dir = Scratch::new("history-clean");
        let key = [0xabu8; 32];
        let upper = hex::encode(key).to_uppercase();
        let path = dir.join(".bash_history");
        let history = format!(
            "ls\n#1700000000\nprintf '{upper}\\ny\\n' | some-script\n#1700000001\nencrypt report.pdf\n#1700000002\ncd /\n"
        );
        fs::write(&path, &history).unwrap();

        let hex = hex::encode(key);
        assert_eq!(clean_file(&path, &Needle { bytes: hex.as_bytes(), any_case: true }).unwrap(), 1);
        // Runs of the tool stay: only the entry with the key goes.
        assert_eq!(fs::read_to_string(&path).unwrap(), "ls\n#1700000001\nencrypt report.pdf\n#1700000002\ncd /\n");

        assert_eq!(clean_file(&dir.join("missing"), &phrase()).unwrap(), 0);
        assert!(!Needle { bytes: b"", any_case: false }.in_entry(b"anything"));
    }

    #[test]
    fn cleans_fish_history() {
        let dir = Scratch::new("history-fish");
        let path = dir.join("fish_history");
        fs::write(&path, "- cmd: ls\n  when: 1\n- cmd: echo 'hunter2 hunter2'\n  when: 2\n- cmd: pwd\n  when: 3\n").unwrap();
        assert_eq!(clean_file(&path, &phrase()).unwrap(), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), "- cmd: ls\n  when: 1\n- cmd: pwd\n  when: 3\n");
    }
}
