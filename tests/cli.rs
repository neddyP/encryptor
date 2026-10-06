//! The command line, end to end: the real binary, run as a script would run
//! it, checked by its exit status, the files it leaves and what it says.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_encryptor");
const PIPE_NOTE: &str = "answering questions through a pipe stops working in 3.0";

/// A folder of its own for one test, with HOME pointed at it so no real shell
/// history is touched, and removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("encryptor-cli-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: &[u8]) {
        fs::write(self.path(name), contents).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    fn run(&self, args: &[&str], stdin: &str) -> Run {
        self.run_as(BIN.as_ref(), args, stdin)
    }

    fn run_as(&self, program: &std::path::Path, args: &[&str], stdin: &str) -> Run {
        let mut child = launcher(program)
            .args(args)
            .current_dir(&self.0)
            .env("HOME", &self.0)
            .env_remove("HISTFILE")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // It may exit without reading, closing the pipe; that's fine.
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        Run(child.wait_with_output().unwrap())
    }

    /// Encrypts `name` with a new key saved as `key`, asking nothing.
    fn encrypt(&self, name: &str, key: &str) {
        let run = self.run(&["encrypt", name, "--new-key", key, "--yes", "--quiet"], "");
        assert_eq!(run.code(), 0, "{}", run.stderr());
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// How to start the binary. Built for another processor, as when `cross`
/// tests arm64 on x64, it can't be run directly, so it goes through the same
/// emulator the tests run under, which cross names in a
/// CARGO_TARGET_*_RUNNER variable.
fn launcher(program: &std::path::Path) -> Command {
    match how_to_run() {
        Some(Some(runner)) => {
            let mut parts = runner.split_whitespace();
            let mut command = Command::new(parts.next().expect("a runner names a program"));
            command.args(parts).arg(program);
            command
        }
        _ => Command::new(program),
    }
}

/// `Some(None)` if the binary runs directly, `Some(Some(runner))` if it
/// runs through an emulator, and `None` if it can't be run here at all.
fn how_to_run() -> &'static Option<Option<String>> {
    static HOW: OnceLock<Option<Option<String>>> = OnceLock::new();
    HOW.get_or_init(|| {
        if Command::new(BIN).arg("--version").output().is_ok() {
            return Some(None);
        }
        let runner = std::env::vars()
            .find(|(name, _)| name.starts_with("CARGO_TARGET_") && name.ends_with("_RUNNER"))
            .map(|(_, runner)| runner);
        match runner {
            Some(runner) => Some(Some(runner)),
            None => {
                eprintln!("skipping: {BIN} can't be run here, directly or through an emulator");
                None
            }
        }
    })
}

/// Whether these tests can run the binary at all.
fn runnable() -> bool {
    how_to_run().is_some()
}

struct Run(Output);

impl Run {
    fn code(&self) -> i32 {
        self.0.status.code().unwrap_or(-1)
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.0.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.0.stderr).into_owned()
    }
}

#[test]
fn round_trips_with_options_and_asks_nothing() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("round-trip");
    let contents: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    dir.write("report.pdf", &contents);

    let run = dir.run(&["encrypt", "report.pdf", "--new-key", "report.key", "--yes"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(run.stdout().contains("ENCRYPTION SUCCESSFUL"));
    assert!(!run.stderr().contains("?"), "asked a question: {}", run.stderr());
    assert!(!dir.exists("report.pdf") && dir.exists("report.pdf.enc") && dir.exists("report.key"));

    let run = dir.run(&["decrypt", "report.pdf.enc", "--key-file", "report.key", "--yes"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(!run.stderr().contains("?"), "asked a question: {}", run.stderr());
    assert_eq!(dir.read("report.pdf"), contents);
}

#[test]
fn saves_a_new_key_into_a_folder() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("key-folder");
    fs::create_dir(dir.path("keys")).unwrap();
    dir.write("notes.txt", b"notes");
    dir.encrypt("notes.txt", "keys");
    assert_eq!(dir.read("keys/notes.txt.key").len(), 32);
}

#[test]
fn refuses_to_save_a_new_key_over_another_file() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("key-taken");
    dir.write("notes.txt", b"notes");
    dir.write("taken.key", b"something else");
    let run = dir.run(&["encrypt", "notes.txt", "--new-key", "taken.key", "--yes"], "");
    assert_eq!(run.code(), 4, "{}", run.stderr());
    assert!(run.stderr().contains("taken.key already exists"));
    assert_eq!(dir.read("taken.key"), b"something else");
    assert!(dir.exists("notes.txt") && !dir.exists("notes.txt.enc"));
}

#[test]
fn keeps_the_original_and_stays_quiet_when_asked() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("keep");
    dir.write("photo.jpg", b"pixels");
    let run = dir.run(&["encrypt", "photo.jpg", "--new-key", "photo.key", "--keep", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.stdout(), "", "printed a report");
    assert_eq!(dir.read("photo.jpg"), b"pixels");
    assert!(dir.exists("photo.jpg.enc"));
}

#[test]
fn writes_the_decrypted_file_where_asked() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("output");
    dir.write("data.bin", b"data");
    dir.encrypt("data.bin", "data.key");
    let run = dir.run(&["decrypt", "data.bin.enc", "-k", "data.key", "-o", "elsewhere.bin", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("elsewhere.bin"), b"data");
    assert!(!dir.exists("data.bin"));
}

#[test]
fn never_takes_overwriting_from_a_pipe() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("overwrite");
    dir.write("report.txt", b"secret");
    dir.encrypt("report.txt", "report.key");
    dir.write("report.txt", b"keep me");

    // As `yes | decrypt ...` would answer.
    let run = dir.run(&["decrypt", "report.txt.enc", "-k", "report.key"], "y\ny\ny\ny\n");
    assert_eq!(run.code(), 2, "{}", run.stderr());
    assert!(run.stderr().contains("Add --overwrite to replace it"), "{}", run.stderr());
    assert_eq!(dir.read("report.txt"), b"keep me");

    let run = dir.run(&["decrypt", "report.txt.enc", "-k", "report.key", "--overwrite", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("report.txt"), b"secret");
}

#[test]
fn reads_keys_as_hex_text_and_from_a_pipe() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("hex-key");
    dir.write("a.txt", b"contents of a");
    dir.encrypt("a.txt", "a.key");
    let hex: String = dir.read("a.key").iter().map(|b| format!("{b:02x}")).collect();
    dir.write("a.hex", format!("{hex}\n").as_bytes());

    let run = dir.run(&["decrypt", "a.txt.enc", "--key-file", "a.hex", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("a.txt"), b"contents of a");

    fs::remove_file(dir.path("a.txt")).unwrap();
    let run = dir.run(&["decrypt", "a.txt.enc", "--key-file", "/dev/stdin", "-y", "-q"], &format!("{hex}\n"));
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("a.txt"), b"contents of a");
}

#[test]
fn exits_with_a_status_scripts_can_act_on() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("codes");
    dir.write("a.txt", b"a");
    dir.encrypt("a.txt", "a.key");
    dir.write("other.key", &[1; 32]);
    dir.write("plain.txt", b"not encrypted");

    let status = |args: &[&str]| dir.run(args, "").code();
    assert_eq!(status(&["decrypt", "a.txt.enc", "-k", "other.key", "-y"]), 3, "wrong key");
    assert_eq!(status(&["decrypt", "missing.enc", "-k", "a.key", "-y"]), 4, "missing file");
    assert_eq!(status(&["decrypt", "plain.txt", "-k", "a.key", "-y"]), 4, "not encrypted");
    assert_eq!(status(&["decrypt", "a.txt.enc", "--force"]), 2, "unknown option");
    assert_eq!(status(&["encrypt", "plain.txt", "--key-file", "a.key", "--new-key", "b.key"]), 2, "conflict");
    assert_eq!(status(&["encrypt", "plain.txt", "a.txt.enc"]), 2, "two files");
    assert_eq!(status(&["decrypt", "a.txt.enc", "--keep"]), 2, "encrypt-only option");
}

#[test]
fn still_takes_piped_answers_but_says_they_are_going() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("piped");
    dir.write("old.txt", b"old style");
    // Generate a key, save it, don't print it, encrypt.
    let run = dir.run(&["encrypt", "old.txt"], "y\ny\nn\ny\n");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(run.stderr().contains(PIPE_NOTE), "{}", run.stderr());
    assert!(dir.exists("old.txt.enc") && dir.exists("old.txt.key"));

    let run = dir.run(&["decrypt", "old.txt.enc"], "old.txt.key\ny\n");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("old.txt"), b"old style");
}

#[test]
fn answers_to_its_names() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("names");
    let link = |name: &str| {
        let path = dir.path(name);
        std::os::unix::fs::symlink(BIN, &path).unwrap();
        path
    };
    let help = dir.run(&["--help"], "");
    assert!(help.stdout().starts_with("encryptor - encrypt and decrypt files"), "{}", help.stdout());
    assert!(dir.run(&["-V"], "").stdout().starts_with("encryptor "));

    let old = dir.run_as(&link("aes256"), &["--version"], "");
    assert_eq!(old.code(), 0);
    assert!(old.stderr().contains("aes256 command is now called encryptor"), "{}", old.stderr());

    dir.write("x.txt", b"x");
    let run = dir.run_as(&link("encrypt"), &["x.txt", "--new-key", "x.key", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let run = dir.run_as(&link("decrypt"), &["x.txt.enc", "-k", "x.key", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("x.txt"), b"x");
}

#[test]
fn updates_only_a_copy_it_knows_how_to_replace() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("update");
    // Built here, it wasn't installed with npm or install.sh.
    let run = dir.run(&["update"], "");
    assert_eq!(run.code(), 1, "{}", run.stderr());
    assert!(run.stderr().contains("can't update itself"), "{}", run.stderr());
    assert_eq!(dir.run(&["update", "x.txt"], "").code(), 2);
    assert_eq!(dir.run(&["update", "--yes"], "").code(), 2);
}

#[test]
fn removes_the_key_and_runs_of_the_tool_from_shell_history() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("history");
    dir.write("a.txt", b"a");
    dir.write("a.key", &[0x5a; 32]);
    let hex = "5A".repeat(32);
    dir.write(
        ".bash_history",
        format!("ls\nencrypt old.txt\necho {hex}\n./target/release/encryptor --help\ncd /\n").as_bytes(),
    );
    dir.write(".zsh_history", b": 1700000000:0;decrypt b.enc\n: 1700000001:0;pwd\n");

    let run = dir.run(&["encrypt", "a.txt", "--key-file", "a.key", "-y"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(
        run.stdout().contains("removed 1 entry holding the key and 3 that ran this tool, from ~/.bash_history, ~/.zsh_history"),
        "{}",
        run.stdout()
    );
    assert_eq!(dir.read(".bash_history"), b"ls\ncd /\n");
    assert_eq!(dir.read(".zsh_history"), b": 1700000001:0;pwd\n");

    // So is a run that stops before a key is asked for.
    dir.write(".bash_history", b"ls\nencrypt missing.txt\n");
    assert_eq!(dir.run(&["encrypt", "missing.txt"], "").code(), 4);
    assert_eq!(dir.read(".bash_history"), b"ls\n");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn removes_the_thumbnails_and_recent_entry_of_the_original() {
    use md5::{Digest, Md5};
    if !runnable() {
        return;
    }
    let dir = Scratch::new("traces");
    dir.write("photo.jpg", b"pixels");
    let uri = format!("file://{}", dir.0.canonicalize().unwrap().join("photo.jpg").display());
    let thumbnail = format!(".cache/thumbnails/large/{}.png", hex::encode(Md5::digest(uri.as_bytes())));
    fs::create_dir_all(dir.path(".cache/thumbnails/large")).unwrap();
    dir.write(&thumbnail, b"a small picture of photo.jpg");
    fs::create_dir_all(dir.path(".local/share")).unwrap();
    let recent = format!("<xbel>\n  <bookmark href=\"{uri}\" added=\"x\">\n  </bookmark>\n</xbel>\n");
    dir.write(".local/share/recently-used.xbel", recent.as_bytes());

    let run = dir.run(&["encrypt", "photo.jpg", "--new-key", "photo.key", "-y"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(run.stdout().contains("removed 1 thumbnail and 1 recently used entry"), "{}", run.stdout());
    assert!(!dir.exists(&thumbnail));
    assert_eq!(dir.read(".local/share/recently-used.xbel"), b"<xbel>\n</xbel>\n");
}

#[test]
fn refuses_a_file_with_other_names_before_asking_for_a_key() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("hard-link");
    dir.write("a.txt", b"a");
    fs::hard_link(dir.path("a.txt"), dir.path("b.txt")).unwrap();
    let run = dir.run(&["encrypt", "a.txt"], "");
    assert_eq!(run.code(), 4, "{}", run.stderr());
    assert!(run.stderr().contains("has 1 other name"), "{}", run.stderr());
    assert!(!run.stderr().contains('?'), "asked a question: {}", run.stderr());
    assert!(!dir.exists("a.txt.enc"));
    assert_eq!(dir.read("b.txt"), b"a");

    let run = dir.run(&["encrypt", "a.txt", "--new-key", "a.key", "--keep", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "kept, it can be encrypted: {}", run.stderr());
}

#[test]
fn overwrites_a_read_only_original() {
    use std::os::unix::fs::PermissionsExt;
    if !runnable() {
        return;
    }
    let dir = Scratch::new("read-only");
    dir.write("ro.txt", b"read only");
    fs::set_permissions(dir.path("ro.txt"), fs::Permissions::from_mode(0o444)).unwrap();
    let run = dir.run(&["encrypt", "ro.txt", "--new-key", "ro.key", "-y"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(run.stdout().contains("overwritten with zeros"), "{}", run.stdout());
    assert!(!dir.exists("ro.txt"));

    let run = dir.run(&["decrypt", "ro.txt.enc", "-k", "ro.key", "-y", "-q"], "");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(dir.read("ro.txt"), b"read only");
    assert_eq!(fs::metadata(dir.path("ro.txt")).unwrap().permissions().mode() & 0o777, 0o444);
}

/// Every Mac disk is APFS, where the original's old contents can't be
/// overwritten. Scripts are warned, but not asked, so piped answers still
/// line up with the questions.
#[cfg(target_os = "macos")]
#[test]
fn warns_a_script_about_a_copy_on_write_disk_without_asking() {
    if !runnable() {
        return;
    }
    let dir = Scratch::new("apfs");
    dir.write("a.txt", b"a");
    let run = dir.run(&["encrypt", "a.txt", "--new-key", "a.key"], "y\n");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(run.stderr().contains("a.txt is on APFS"), "{}", run.stderr());
    assert!(!run.stderr().contains("Encrypt anyway?"), "{}", run.stderr());
    assert!(dir.exists("a.txt.enc") && !dir.exists("a.txt"));
}
