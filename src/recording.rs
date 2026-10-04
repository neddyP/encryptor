//! Finding what records or shares this terminal session, so a key is never
//! printed where a recording would keep it.
//!
//! Recorders such as `script` and `asciinema` start the shell themselves, so
//! they are found among this program's ancestors. tmux keeps no copy of the
//! alternate screen a key is shown on, but `pipe-pane` copies a pane's output
//! to another program, and each client showing the pane can run inside a
//! recorder of its own. On Linux a debugger or tracer attached to this program
//! sees everything it writes. Terminal emulator logs, sudo I/O logs and
//! recorders on the far side of an SSH connection can't be seen from here.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::term::safe;

/// Programs that record, log or share what is shown in the terminal they run,
/// and what each does with it.
const KNOWN: &[(&str, &str)] = &[
    ("script", "records the terminal session"),
    ("asciinema", "records or streams the terminal session"),
    ("ttyrec", "records the terminal session"),
    ("termrec", "records the terminal session"),
    ("tlog-rec", "records the terminal session to the system log"),
    ("tlog-rec-session", "records the terminal session to the system log"),
    ("terminalizer", "records the terminal session"),
    ("vhs", "records the terminal to a video"),
    ("t-rec", "records the terminal window to a video"),
    ("rootsh", "logs the terminal session"),
    ("sudosh", "logs the terminal session"),
    ("screen", "may keep what is shown in its scrollback or log file"),
    ("tmate", "shares the terminal with other people"),
    ("tty-share", "shares the terminal with other people"),
    ("upterm", "shares the terminal with other people"),
    ("sshx", "shares the terminal with other people"),
    ("ttyd", "serves the terminal to web browsers"),
    ("gotty", "serves the terminal to web browsers"),
];

/// Recorders written in Python or JavaScript. They run under an interpreter,
/// so they show up as its first argument rather than by name.
const RUN_BY_INTERPRETER: &[&str] = &["asciinema", "terminalizer"];

/// Ancestors checked before giving up, in case of a loop.
const MAX_ANCESTORS: usize = 64;

/// Something that would capture a key shown on this terminal.
pub struct Recorder {
    program: String,
    pid: Option<u32>,
    what: String,
    /// What it writes to, and how it sees this terminal if not directly.
    details: Vec<String>,
}

impl fmt::Display for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  - {}", safe(&self.program))?;
        if let Some(pid) = self.pid {
            write!(f, " (PID {pid})")?;
        }
        writeln!(f, ": {}", self.what)?;
        for line in &self.details {
            writeln!(f, "      {}", safe(line))?;
        }
        Ok(())
    }
}

/// The recorders' program names for a sentence, such as "script and tmux
/// pipe-pane", each named once.
pub fn names(recorders: &[Recorder]) -> String {
    let mut names: Vec<String> = Vec::new();
    for recorder in recorders {
        let name = safe(&recorder.program);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    match names.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    }
}

/// Everything found that would capture what this program shows on its
/// terminal. Empty if nothing was found.
pub fn scan() -> Vec<Recorder> {
    let mut found = Vec::new();
    examine(std::process::id(), None, &mut found);
    examine_tmux(&mut found);

    // The variables these programs set, in case the program itself wasn't
    // recognised.
    let seen = |program: &str| found.iter().any(|r| r.program == program);
    let asciinema = env::var_os("ASCIINEMA_REC").is_some() && !seen("asciinema");
    let screen = env::var("STY").ok().filter(|_| !seen("screen"));
    if asciinema {
        found.push(Recorder {
            program: "asciinema".into(),
            pid: None,
            what: describe("asciinema").into(),
            details: vec!["ASCIINEMA_REC is set, which asciinema does in sessions it records".into()],
        });
    }
    if let Some(session) = screen {
        found.push(Recorder {
            program: "screen".into(),
            pid: None,
            what: describe("screen").into(),
            details: vec![format!("session {session}")],
        });
    }
    found
}

fn describe(program: &str) -> &'static str {
    KNOWN.iter().find(|(name, _)| *name == program).map_or("", |(_, what)| what)
}

/// Looks for recorders among `pid` and its ancestors, and for a tracer
/// attached to `pid`. `client` is the terminal of the tmux client `pid` is,
/// when it isn't this program.
fn examine(pid: u32, client: Option<&str>, found: &mut Vec<Recorder>) {
    let Some(first) = process(pid) else { return };

    if let Some(tracer) = first.tracer {
        let traced = match client {
            Some(tty) => format!("the tmux client on {tty}, which shows this pane,"),
            None => "this program".into(),
        };
        let name = process(tracer).and_then(|t| t.names.into_iter().find(|n| !n.is_empty()));
        found.push(Recorder {
            program: name.unwrap_or_else(|| "a debugger or tracer".into()),
            pid: Some(tracer),
            what: format!("is tracing {traced} and sees everything it writes"),
            details: writing_to(tracer),
        });
    }

    let (mut pid, mut p) = (pid, first);
    for _ in 0..MAX_ANCESTORS {
        if let Some((name, what)) = recorder_named(&p.names) {
            if !(name == "script" && records_nothing(pid)) {
                let mut details: Vec<String> = client
                    .map(|tty| format!("the tmux client on {tty} runs inside it and shows this pane"))
                    .into_iter()
                    .collect();
                details.extend(writing_to(pid));
                found.push(Recorder { program: name.into(), pid: Some(pid), what: what.into(), details });
            }
        }
        if p.ppid == 0 || p.ppid == pid {
            break;
        }
        pid = p.ppid;
        match process(pid) {
            Some(parent) => p = parent,
            None => break,
        }
    }
}

fn recorder_named(names: &[String]) -> Option<(&'static str, &'static str)> {
    KNOWN.iter().copied().find(|(known, _)| {
        // Linux cuts command names to 15 bytes.
        names.iter().any(|name| name == known || (name.len() == 15 && known.starts_with(name.as_str())))
    })
}

/// Checks the tmux pane this program runs in, if any, for `pipe-pane`, and the
/// clients showing it for recorders and tracers of their own.
fn examine_tmux(found: &mut Vec<Recorder>) {
    let (Some(var), Ok(pane)) = (env::var_os("TMUX"), env::var("TMUX_PANE")) else { return };
    let Some(socket) = tmux_socket(var.as_bytes()) else { return };

    let Some(info) = tmux(socket, &["display-message", "-p", "-t", &pane, "#{pane_pipe} #{session_id}"])
    else {
        return;
    };
    let mut info = info.split_whitespace();
    let (Some(piped), Some(session)) = (info.next(), info.next()) else { return };
    if piped == "1" {
        found.push(Recorder {
            program: "tmux pipe-pane".into(),
            pid: None,
            what: "copies everything shown in this pane to another program".into(),
            details: Vec::new(),
        });
    }

    let Some(clients) = tmux(socket, &["list-clients", "-t", session, "-F", "#{client_pid} #{client_tty}"])
    else {
        return;
    };
    for line in clients.lines() {
        if let Some((Ok(pid), tty)) = line.split_once(' ').map(|(pid, tty)| (pid.parse(), tty)) {
            examine(pid, Some(tty), found);
        }
    }
}

/// The server socket from `$TMUX`, which tmux sets to "socket,pid,session".
fn tmux_socket(var: &[u8]) -> Option<&OsStr> {
    let mut parts = var.rsplitn(3, |&b| b == b',');
    let (_, _, socket) = (parts.next()?, parts.next()?, parts.next()?);
    Some(OsStr::from_bytes(socket)).filter(|s| !s.is_empty())
}

/// Runs a tmux command against the server at `socket` and returns its output,
/// giving up after a second rather than hang on a server that doesn't answer.
fn tmux(socket: &OsStr, args: &[&str]) -> Option<String> {
    let mut child = Command::new("tmux")
        .arg("-S")
        .arg(socket)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    Some(out)
}

struct Process {
    ppid: u32,
    /// The names it goes by: its command name, the program it was started as,
    /// and the recorder an interpreter is running.
    names: Vec<String>,
    /// A debugger or tracer attached to it (Linux only).
    tracer: Option<u32>,
}

#[cfg(target_os = "linux")]
fn process(pid: u32) -> Option<Process> {
    let dir = format!("/proc/{pid}");
    let status = std::fs::read(format!("{dir}/status")).ok()?;
    let status = String::from_utf8_lossy(&status);
    let comm = std::fs::read(format!("{dir}/comm")).unwrap_or_default();
    let cmdline = std::fs::read(format!("{dir}/cmdline")).unwrap_or_default();
    Some(Process {
        ppid: status_field(&status, "PPid")?,
        names: process_names(&comm, &cmdline),
        tracer: status_field(&status, "TracerPid").filter(|&tracer| tracer != 0),
    })
}

/// A number from /proc/<pid>/status, such as "PPid:\t1234".
#[cfg(target_os = "linux")]
fn status_field(status: &str, name: &str) -> Option<u32> {
    status.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(':')?.trim().parse().ok())
}

/// The names a Linux process goes by, from /proc/<pid>/comm and cmdline.
#[cfg(target_os = "linux")]
fn process_names(comm: &[u8], cmdline: &[u8]) -> Vec<String> {
    let mut names = vec![String::from_utf8_lossy(comm).trim_end().to_string()];
    let mut args = cmdline.split(|&b| b == 0).filter(|arg| !arg.is_empty()).map(base_name);
    if let Some(program) = args.next() {
        // A login shell is started with a '-' in front of its name.
        let program = program.strip_prefix('-').unwrap_or(&program).to_string();
        if ["python", "node", "ruby", "perl"].iter().any(|i| program.starts_with(i)) {
            let script = args.find(|arg| !arg.starts_with('-'));
            names.extend(script.filter(|s| RUN_BY_INTERPRETER.contains(&s.as_str())));
        }
        names.push(program);
    }
    names
}

#[cfg(target_os = "macos")]
fn process(pid: u32) -> Option<Process> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_bsdinfo is plain data. proc_pidinfo writes at most `size`
    // bytes into it and returns how many it wrote.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) } != size {
        return None;
    }
    let mut names = vec![c_chars(&info.pbi_comm), c_chars(&info.pbi_name)];
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most `path.len()` bytes into `path`.
    let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if len > 0 {
        names.push(base_name(&path[..len as usize]));
    }
    Some(Process { ppid: info.pbi_ppid, names, tracer: None })
}

#[cfg(target_os = "macos")]
fn c_chars(chars: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = chars.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process(_: u32) -> Option<Process> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn base_name(path: &[u8]) -> String {
    let path = std::path::Path::new(OsStr::from_bytes(path));
    path.file_name().unwrap_or(path.as_os_str()).to_string_lossy().into_owned()
}

/// Something a process has open for writing, other than a terminal.
#[cfg(target_os = "linux")]
#[derive(PartialEq)]
enum Output {
    File(String),
    Socket,
    Pipe,
    Null,
}

/// What a process has open for writing, or `None` if that can't be seen.
#[cfg(target_os = "linux")]
fn outputs(pid: u32) -> Option<Vec<Output>> {
    use std::os::unix::fs::FileTypeExt;

    let dir = format!("/proc/{pid}/fd");
    let mut outputs = Vec::new();
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let fd = entry.file_name();
        let fd = fd.to_string_lossy();
        let Ok(target) = std::fs::read_link(format!("{dir}/{fd}")) else { continue };
        let flags = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok().and_then(|info| {
            let flags = info.lines().find_map(|line| line.strip_prefix("flags:"))?;
            u32::from_str_radix(flags.trim(), 8).ok()
        });
        if flags.is_some_and(|flags| flags & libc::O_ACCMODE as u32 == libc::O_RDONLY as u32) {
            continue;
        }
        let target = target.as_os_str().as_bytes();
        let kind = std::fs::metadata(format!("{dir}/{fd}")).map(|meta| meta.file_type());
        outputs.push(match target {
            b"/dev/null" => Output::Null,
            _ if target.starts_with(b"socket:") => Output::Socket,
            _ if target.starts_with(b"pipe:") || kind.as_ref().is_ok_and(|k| k.is_fifo()) => Output::Pipe,
            _ if kind.is_ok_and(|k| k.is_file()) => Output::File(String::from_utf8_lossy(target).into()),
            // Terminals and other devices, and kernel objects like signalfds.
            _ => continue,
        });
    }
    Some(outputs)
}

/// Where a process is writing, as lines for the report.
#[cfg(target_os = "linux")]
fn writing_to(pid: u32) -> Vec<String> {
    let mut lines: Vec<String> = outputs(pid)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|output| match output {
            Output::File(path) => Some(format!("writing to {path}")),
            Output::Socket => Some("has a network or local socket open".into()),
            Output::Pipe | Output::Null => None,
        })
        .collect();
    lines.sort();
    lines.dedup();
    lines
}

/// Whether a `script` process is writing its recording to /dev/null, the usual
/// way to give a command a terminal without recording anything.
#[cfg(target_os = "linux")]
fn records_nothing(pid: u32) -> bool {
    outputs(pid).is_some_and(|outputs| {
        outputs.contains(&Output::Null) && outputs.iter().all(|output| *output == Output::Null)
    })
}

#[cfg(not(target_os = "linux"))]
fn writing_to(_: u32) -> Vec<String> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
fn records_nothing(_: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_recorders_safely() {
        let recorder = Recorder {
            program: "script".into(),
            pid: Some(42),
            what: "records the terminal session".into(),
            details: vec!["writing to /tmp/log\x1b[2J".into()],
        };
        assert_eq!(
            recorder.to_string(),
            "  - script (PID 42): records the terminal session\n      writing to /tmp/log\\u{1b}[2J\n"
        );
    }

    #[test]
    fn names_recorders_for_a_sentence() {
        let named = |programs: &[&str]| {
            let recorders: Vec<Recorder> = programs
                .iter()
                .map(|program| Recorder {
                    program: program.to_string(),
                    pid: None,
                    what: String::new(),
                    details: Vec::new(),
                })
                .collect();
            names(&recorders)
        };
        assert_eq!(named(&["script"]), "script");
        assert_eq!(named(&["script", "tmux pipe-pane"]), "script and tmux pipe-pane");
        assert_eq!(named(&["script", "screen", "script", "strace"]), "script, screen and strace");
        assert_eq!(named(&["evil\x1b[2J"]), "evil\\u{1b}[2J");
    }

    #[test]
    fn finds_the_tmux_socket() {
        assert_eq!(tmux_socket(b"/tmp/tmux-1000/default,1234,0"), Some(OsStr::new("/tmp/tmux-1000/default")));
        assert_eq!(tmux_socket(b"/tmp/a,b/sock,1234,0"), Some(OsStr::new("/tmp/a,b/sock")));
        assert_eq!(tmux_socket(b"/tmp/sock"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn reads_this_process() {
        let me = process(std::process::id()).unwrap();
        assert_eq!(me.ppid, std::os::unix::process::parent_id());
        assert!(me.names.iter().any(|name| !name.is_empty()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recognises_recorders_by_any_name() {
        let named = |comm: &str, cmdline: &str| {
            recorder_named(&process_names(comm.as_bytes(), cmdline.replace(' ', "\0").as_bytes())).map(|r| r.0)
        };
        assert_eq!(named("script\n", "script -q /tmp/log"), Some("script"));
        // A 15-byte command name, and a login shell's '-'.
        assert_eq!(named("tlog-rec-sessio\n", ""), Some("tlog-rec-session"));
        assert_eq!(named("bash\n", "-tlog-rec-session"), Some("tlog-rec-session"));
        // Interpreted recorders, run as a file or as a module.
        assert_eq!(named("python3\n", "/usr/bin/python3 /usr/bin/asciinema rec"), Some("asciinema"));
        assert_eq!(named("python3\n", "python3 -m asciinema rec"), Some("asciinema"));
        assert_eq!(named("node\n", "node /usr/local/bin/terminalizer record demo"), Some("terminalizer"));
        // Any other script is just a script.
        assert_eq!(named("python3\n", "python3 ./script"), None);
        assert_eq!(named("bash\n", "bash"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_status_fields() {
        let status = "Name:\tbash\nPid:\t42\nPPid:\t7\nTracerPid:\t0\n";
        assert_eq!(status_field(status, "PPid"), Some(7));
        assert_eq!(status_field(status, "Pid"), Some(42));
        assert_eq!(status_field(status, "TracerPid"), Some(0));
        assert_eq!(status_field(status, "Uid"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sees_what_a_process_writes_to() {
        let dir = std::env::temp_dir().join(format!("encryptor-recording-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("session.log");
        let sleep = |stdout: Stdio| {
            Command::new("sleep").arg("10").stdin(Stdio::null()).stdout(stdout).stderr(Stdio::null()).spawn()
        };
        let mut logging = sleep(std::fs::File::create(&log).unwrap().into()).unwrap();
        let mut silent = sleep(Stdio::null()).unwrap();

        let logging_writes = writing_to(logging.id());
        let logging_records = !records_nothing(logging.id());
        let silent_writes = writing_to(silent.id());
        let silent_records = !records_nothing(silent.id());
        let log = std::fs::canonicalize(&log).unwrap();
        for child in [&mut logging, &mut silent] {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(logging_writes, [format!("writing to {}", log.display())]);
        assert!(logging_records);
        assert!(silent_writes.is_empty());
        assert!(!silent_records, "writing only to /dev/null records nothing");
    }
}
