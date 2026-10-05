//! Shell history: removing every entry that holds a key or ran this tool from
//! bash, zsh and fish history files, including the history macOS's Terminal
//! keeps for each window, so neither the key nor the fact the tool was used is
//! left there. Each file is rewritten in place and the bytes left
//! over are zeroed before it is cut short, so removed entries don't linger in
//! freed disk blocks.
//!
//! A shell keeps its own session's history in memory and writes it out when it
//! exits, after this program has finished, so the command that ran it is only
//! removed by a later run, unless the shell was told not to save it (with
//! bash's HISTCONTROL=ignorespace, zsh's HIST_IGNORE_SPACE, or in fish, by
//! starting the command with a space).

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::term::safe_path;
use crate::wipe;

/// The commands this tool can be run as.
const NAMES: [&str; 4] = ["encrypt", "decrypt", "encryptor", "aes256"];

/// Folders where macOS's Terminal keeps a history file for each window, as
/// bash and zsh are set up there (/etc/bashrc_Apple_Terminal and
/// /etc/zshrc_Apple_Terminal): `<window>.history`, and `<window>.historynew`
/// while a window is open.
const SESSION_FOLDERS: [&str; 2] = [".bash_sessions", ".zsh_sessions"];

/// Shell history files that could hold a key typed or pasted into a command,
/// or a command that ran this tool.
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

/// Removes every entry holding `key`, if one is given, and every entry that
/// ran this tool, from each shell history file, and describes what was done.
pub fn clean(key: Option<&[u8; KEY_LEN]>) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let shown = |path: &Path| match home.as_deref().and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", safe_path(rest)),
        None => safe_path(path),
    };
    let mut hex = Zeroizing::new([0u8; 2 * KEY_LEN]);
    if let Some(key) = key {
        hex::encode_to_slice(key, &mut hex[..]).expect("a 32-byte key is 64 hex characters");
    }
    let hex = key.map(|_| &hex[..]);

    let mut total = Removed::default();
    let mut cleaned = Vec::new();
    let mut unreadable = Vec::new();
    for path in files() {
        match clean_file(&path, hex) {
            Ok(removed) if removed.any() => {
                total.key += removed.key;
                total.runs += removed.runs;
                cleaned.push(path);
            }
            Ok(_) => {}
            Err(e) => unreadable.push(format!("{} ({e})", shown(&path))),
        }
    }
    let mut status = match (total.key, total.runs) {
        (0, 0) if key.is_some() => "no entries held the key or ran this tool".to_string(),
        (0, 0) => "no entries ran this tool".to_string(),
        (0, ran) => format!("removed {} that ran this tool", entries(ran)),
        (held, 0) => format!("removed {} holding the key", entries(held)),
        (held, ran) => format!("removed {} holding the key and {ran} that ran this tool", entries(held)),
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

/// How many entries were removed from a file, and why.
#[derive(Default)]
struct Removed {
    key: usize,
    runs: usize,
}

impl Removed {
    fn any(&self) -> bool {
        self.key + self.runs > 0
    }
}

/// Removes the entries holding `hex` or running this tool from one history
/// file. A missing file has none.
fn clean_file(path: &Path, hex: Option<&[u8]>) -> io::Result<Removed> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removed::default()),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let mut contents = Zeroizing::new(vec![0u8; usize::try_from(len).map_err(io::Error::other)?]);
    file.read_exact_at(&mut contents, 0)?;

    let fish = path.file_name().is_some_and(|name| name == "fish_history");
    let mut kept = Zeroizing::new(Vec::with_capacity(contents.len()));
    let mut removed = Removed::default();
    for entry in split_entries(&contents, fish) {
        if hex.is_some_and(|hex| entry.windows(hex.len()).any(|w| w.eq_ignore_ascii_case(hex))) {
            removed.key += 1;
        } else if runs_tool(&command(entry, fish)) {
            removed.runs += 1;
        } else {
            kept.extend_from_slice(entry);
        }
    }
    if removed.any() {
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

/// The command an entry records, without the timestamps around it.
fn command(entry: &[u8], fish: bool) -> String {
    let text = String::from_utf8_lossy(entry);
    if fish {
        // Fish writes a command's line breaks as \n.
        let first = text.lines().next().unwrap_or_default();
        return first.strip_prefix("- cmd: ").unwrap_or(first).replace("\\n", "\n");
    }
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.first().is_some_and(|line| line.len() > 1 && line.starts_with('#') && line[1..].bytes().all(|b| b.is_ascii_digit())) {
        lines.remove(0);
    }
    // zsh ends each line of a multi-line command but the last with a backslash.
    let joined = lines.iter().map(|line| line.strip_suffix('\\').unwrap_or(line)).collect::<Vec<_>>().join("\n");
    // zsh's extended format starts with `: <time>:<duration>;`.
    match joined.strip_prefix(": ").and_then(|rest| rest.split_once(';')) {
        Some((times, command)) if times.bytes().all(|b| b.is_ascii_digit() || b == b':') => command.to_string(),
        _ => joined,
    }
}

/// Whether a command line runs this tool anywhere in it: as the command, or
/// after a pipe, `;`, `&&` or the like, through sudo, env or npx, or by path.
fn runs_tool(command: &str) -> bool {
    simple_commands(command).iter().any(|words| invokes_tool(words))
}

fn invokes_tool(words: &[String]) -> bool {
    let mut words = words.iter().map(String::as_str).peekable();
    while let Some(word) = words.next() {
        let assignment = word.split_once('=').is_some_and(|(name, _)| {
            name.bytes().next().is_some_and(|b| b == b'_' || b.is_ascii_alphabetic())
                && name.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric())
        });
        match word {
            _ if assignment => {}
            "sudo" | "doas" | "env" | "command" | "builtin" | "exec" | "nohup" | "time" | "nice" | "!" | "{"
            | "if" | "then" | "else" | "elif" | "while" | "until" | "do" => {
                // Their options, with the value of those that take one.
                while let Some(option) = words.next_if(|w| w.starts_with('-')) {
                    if matches!(option, "-u" | "-g" | "-n" | "-C") {
                        words.next();
                    }
                }
            }
            "npx" | "bunx" | "pnpx" => {
                return words.any(|w| {
                    let name = w.rsplit('/').next().unwrap_or(w);
                    name.split('@').next() == Some("encryptor")
                });
            }
            _ => return NAMES.contains(&word.rsplit('/').next().unwrap_or(word)),
        }
    }
    false
}

/// The simple commands in a command line, as their words with quotes taken
/// off. It's split at `;`, `&`, `|`, brackets, backquotes and line breaks
/// outside quotes, which is enough to find the command each part runs.
fn simple_commands(command: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote = None;
    let mut chars = command.chars();
    let end_word = |words: &mut Vec<String>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => word.extend(chars.next()),
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => match chars.next() {
                // A line continued on the next.
                Some('\n') => {}
                escaped => {
                    word.extend(escaped);
                    in_word = true;
                }
            },
            (None, ';' | '&' | '|' | '(' | ')' | '`' | '\n') => {
                end_word(&mut words, &mut word, &mut in_word);
                commands.push(std::mem::take(&mut words));
            }
            (None, c) if c.is_whitespace() => end_word(&mut words, &mut word, &mut in_word),
            (None, c) => {
                word.push(c);
                in_word = true;
            }
        }
    }
    end_word(&mut words, &mut word, &mut in_word);
    commands.push(words);
    commands.retain(|words| !words.is_empty());
    commands
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn includes_terminal_window_history_on_macos() {
        let home = scratch("sessions");
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

        let files = history_files(Some(home.clone()), None, Some(zdot), None);
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

    #[test]
    fn cleans_a_terminal_window_history_file() {
        let dir = scratch("window").join(".bash_sessions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("A.history");
        fs::write(&path, b"ls\nencrypt report.pdf\ncd ~\n").unwrap();
        assert_eq!(clean_file(&path, None).unwrap().runs, 1);
        assert_eq!(fs::read(&path).unwrap(), b"ls\ncd ~\n");
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encryptor-history-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn recognises_commands_that_run_the_tool() {
        for command in [
            "encrypt report.pdf",
            "decrypt report.pdf.enc --key-file k.key",
            "encryptor",
            "aes256 encrypt a",
            "./target/release/encryptor encrypt a",
            "~/bin/decrypt a.enc",
            "cd docs && encrypt a",
            "ls; encrypt a",
            "printf 'y\\n' | encrypt a",
            "KEY=1 encrypt a",
            "sudo -u bob encrypt a",
            "env -i HOME=/x decrypt a.enc",
            "time encrypt big.iso",
            "(cd x; encrypt a)",
            "echo $(decrypt a.enc)",
            "npx @neddyp/encryptor encrypt a",
            "npx -p @neddyp/encryptor@2.1.0 encrypt a",
            "\"encrypt\" a",
            "if true; then encrypt a; fi",
        ] {
            assert!(runs_tool(command), "{command}");
        }
        for command in [
            "ls",
            "cat bin/encrypt",
            "vim src/encrypt.rs",
            "gpg --encrypt a",
            "git commit -m 'encrypt files in chunks'",
            "echo \"decrypt a | encrypt b\"",
            "grep -rn encryptor .",
            "npm install -g @neddyp/encryptor",
            "",
        ] {
            assert!(!runs_tool(command), "{command}");
        }
    }

    #[test]
    fn splits_entries_in_each_format() {
        let bash = b"ls\n#1700000000\nencrypt a\n#1700000001\ncd /\n";
        assert_eq!(split_entries(bash, false), [&b"ls\n"[..], b"#1700000000\nencrypt a\n", b"#1700000001\ncd /\n"]);
        assert_eq!(command(b"#1700000000\nencrypt a\n", false), "encrypt a");

        let zsh = b": 1700000000:0;ls\n: 1700000001:2;for f in *; do\\\nencrypt $f\\\ndone\n";
        let entries = split_entries(zsh, false);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1], &zsh[18..]);
        assert!(runs_tool(&command(entries[1], false)));

        let fish = b"- cmd: ls\n  when: 1700000000\n- cmd: encrypt a\n  when: 1700000001\n  paths:\n    - a\n";
        let entries = split_entries(fish, true);
        assert_eq!(entries, [&b"- cmd: ls\n  when: 1700000000\n"[..], &fish[29..]]);
        assert_eq!(command(entries[1], true), "encrypt a");
    }

    #[test]
    fn removes_whole_entries() {
        let dir = scratch("clean");
        let key = [0xabu8; 32];
        let upper = hex::encode(key).to_uppercase();
        let path = dir.join(".bash_history");
        let history = format!(
            "ls\n#1700000000\nprintf '{upper}\\ny\\n' | some-script\n#1700000001\nencrypt report.pdf\n#1700000002\ncd /\n"
        );
        fs::write(&path, &history).unwrap();

        let removed = clean_file(&path, Some(hex::encode(key).as_bytes())).unwrap();
        assert_eq!((removed.key, removed.runs), (1, 1));
        assert_eq!(fs::read_to_string(&path).unwrap(), "ls\n#1700000002\ncd /\n");

        assert_eq!(clean_file(&path, None).unwrap().any(), false);
        assert_eq!(clean_file(&dir.join("missing"), None).unwrap().any(), false);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleans_fish_history() {
        let dir = scratch("fish");
        let path = dir.join("fish_history");
        fs::write(&path, "- cmd: ls\n  when: 1\n- cmd: decrypt a.enc\n  when: 2\n  paths:\n    - a.enc\n- cmd: pwd\n  when: 3\n")
            .unwrap();
        let removed = clean_file(&path, None).unwrap();
        assert_eq!((removed.key, removed.runs), (0, 1));
        assert_eq!(fs::read_to_string(&path).unwrap(), "- cmd: ls\n  when: 1\n- cmd: pwd\n  when: 3\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
