//! Terminal input and output that leave no secrets behind: unbuffered reads
//! into fixed-size buffers that are wiped afterwards, hidden key entry, keys
//! shown only on the terminal's alternate screen, and escaping of untrusted
//! text before it is printed.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::{protect, session};

/// Longest line accepted at a prompt. Line buffers are allocated at this size
/// up front because growing them would leave copies of the input behind.
const MAX_LINE: usize = 4096;

/// Prints `prompt` and reads one line from standard input. Reads are
/// unbuffered, so no copy of the line stays in a library buffer. Surrounding
/// whitespace is removed.
pub fn read_line(prompt: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        note_piped_answers();
    }
    show_prompt(prompt)?;
    let mut line = line_buffer();
    loop {
        match read_byte(libc::STDIN_FILENO)? {
            None if line.is_empty() => return Err(input_ended().into()),
            None | Some(b'\n') => break,
            Some(byte) => push(&mut line, byte)?,
        }
    }
    finish(line)
}

/// Reads a key without echoing it. On a terminal, typing is hidden and
/// Backspace, Ctrl-U (clear) and Ctrl-C (cancel) work, and the prompt goes to
/// standard error so it stays visible when standard output is redirected.
/// Piped input is read as an ordinary line so the tool can be scripted.
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        return read_line(prompt);
    }
    eprint!("{prompt}");
    let mut line = line_buffer();
    {
        let _raw = RawMode::enter(libc::STDIN_FILENO)?;
        loop {
            match read_byte(libc::STDIN_FILENO)? {
                None | Some(b'\r' | b'\n') => break,
                Some(0x03) => {
                    protect::request_stop();
                    eprintln!();
                    return Err(Error::Interrupted);
                }
                Some(0x04) if line.is_empty() => return Err(input_ended().into()),
                Some(0x7f | 0x08) => pop_char(&mut line),
                Some(0x15) => line.clear(),
                Some(0x1b) => skip_escape_sequence(libc::STDIN_FILENO)?,
                Some(byte) if byte < 0x20 => {}
                Some(byte) => push(&mut line, byte)?,
            }
        }
    }
    eprintln!();
    finish(line)
}

/// Why a key couldn't be shown.
pub enum Shown {
    Yes,
    Unavailable(&'static str),
}

/// Shows `key`, hex-encoded, on the terminal's alternate screen (the one full
/// screen programs like `less` use), which keeps no scrollback. Waits for
/// Enter, then erases it and returns to the normal screen. In a session, the
/// run is on the alternate screen already: the key takes it over, and once
/// erased, the session's art and what was done so far are drawn again.
/// Everything is written straight to the terminal device, so the key never
/// goes through standard output and can't end up in a redirected file.
pub fn show_key(key: &[u8; 32]) -> Result<Shown> {
    let term = std::env::var("TERM").unwrap_or_default();
    if term.is_empty() || term == "dumb" {
        return Ok(Shown::Unavailable("the terminal type (TERM) is unset or \"dumb\", so it couldn't be erased afterwards"));
    }
    let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return Ok(Shown::Unavailable("there's no terminal to show it on, as the tool isn't running in a terminal window"));
    };

    let mut hex = Zeroizing::new([0u8; 64]);
    protect::lock(hex.as_ptr(), hex.len());
    hex::encode_to_slice(key, &mut hex[..]).expect("a 32-byte key is 64 hex characters");

    let in_session = session::active();
    let (open, close): (&[u8], &[u8]) = match in_session {
        true => (b"\x1b[H\x1b[2J", b"\x1b[H\x1b[2J"),
        false => (b"\x1b[?1049h\x1b[2J\x1b[H", b"\x1b[2J\x1b[H\x1b[?1049l"),
    };
    let fd = tty.as_raw_fd();
    let _ = io::stdout().flush();
    let raw = RawMode::enter(fd)?;
    let shown = tty
        .write_all(open)
        .and_then(|()| tty.write_all(b"Your encryption key (shown once):\r\n\r\n    "))
        .and_then(|()| tty.write_all(&hex[..]))
        .and_then(|()| {
            tty.write_all(
                b"\r\n\r\nWrite it down or put it in a password manager. Without it the file\r\n\
                  cannot be decrypted.\r\n\r\n\
                  Selecting it to copy puts it on your clipboard, which compromises\r\n\
                  your security: clipboard history keeps a copy. Type it in instead.\r\n\r\n",
            )
        })
        // The prompt on the bottom row, when there's room below the key.
        .and_then(|()| match rows(fd) {
            Some(rows) if rows > 9 => tty.write_all(format!("\x1b[{rows};1H").as_bytes()),
            _ => Ok(()),
        })
        .and_then(|()| tty.write_all(b"Press Enter to erase the key and go back."))
        .map_err(|e| Error::from(format!("cannot write to terminal: {e}")));
    let result = shown.and_then(|()| wait_for_enter(fd));
    // Erase it even after an error or Ctrl-C. Only the screen: erasing
    // scrollback as well (ESC [3J) could reach the window's own history.
    let _ = tty.write_all(close);
    drop(raw);
    if in_session {
        session::header();
    }
    result.map(|()| Shown::Yes)
}

/// Rows of the terminal on `fd`, if it says.
fn rows(fd: libc::c_int) -> Option<u16> {
    // SAFETY: winsize is plain data, filled in by the ioctl.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: asks the terminal on `fd` for its size.
    let known = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0;
    (known && size.ws_row > 0).then_some(size.ws_row)
}

/// Waits for Enter at the terminal on standard input. Ctrl-C returns
/// `Interrupted`.
pub fn press_enter() -> Result<()> {
    let _raw = RawMode::enter(libc::STDIN_FILENO)?;
    wait_for_enter(libc::STDIN_FILENO)
}

/// A progress line on standard error for long jobs, shown only on a terminal
/// and for large files, and cleared when dropped.
pub struct Progress {
    label: &'static str,
    total: u64,
    shown: bool,
    last: Instant,
}

impl Progress {
    pub fn new(label: &'static str, total: u64) -> Self {
        let shown = total >= 64 << 20 && io::stderr().is_terminal();
        Self { label, total, shown, last: Instant::now() }
    }

    /// Whether the line is being shown at all.
    pub fn shown(&self) -> bool {
        self.shown
    }

    pub fn update(&mut self, done: u64) {
        if !self.shown || self.last.elapsed() < Duration::from_millis(250) {
            return;
        }
        self.last = Instant::now();
        eprint!("\r{} {:>3}% of {}\x1b[K", self.label, done * 100 / self.total, short_size(self.total));
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.shown {
            eprint!("\r\x1b[K");
        }
    }
}

fn short_size(bytes: u64) -> String {
    let mut value = bytes as f64;
    let mut unit = "bytes";
    for next in ["KiB", "MiB", "GiB", "TiB"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// Makes untrusted text such as file names safe to print: control characters
/// and Unicode direction overrides are shown as escapes, so a crafted name
/// can't move the cursor, change colours or fake lines of output.
pub fn safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_direction_control(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn safe_path(path: &Path) -> String {
    safe(&path.to_string_lossy())
}

fn is_direction_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Says once that answering questions through a pipe is on its way out, in
/// favour of options, which can't land on the wrong question.
fn note_piped_answers() {
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !NOTED.swap(true, Ordering::SeqCst) {
        eprintln!("note: answering questions through a pipe stops working in 3.0. Use options instead,");
        eprintln!("such as --key-file, --new-key and --yes; see encryptor --help.");
    }
}

/// Input that ran out before a question was answered.
fn input_ended() -> String {
    if io::stdin().is_terminal() {
        "input ended (Ctrl-D) before the question was answered".into()
    } else {
        "the answers piped in ran out before every question was answered.\n\
         Give one line per question, in the order they're asked; see Scripting in the README."
            .into()
    }
}

/// Prompts and other conversation go to standard error, so redirecting
/// standard output, where the report goes, doesn't hide them.
fn show_prompt(prompt: &str) -> Result<()> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|e| format!("cannot write to terminal: {e}").into())
}

pub fn confirm(question: &str) -> Result<bool> {
    Ok(choose(question, &["yes", "no"])? == "yes")
}

/// Asks until the answer is one of `options`, typed in full or as its first
/// letter, and returns the chosen option.
pub fn choose<'a>(question: &str, options: &[&'a str]) -> Result<&'a str> {
    let letters: Vec<&str> = options.iter().map(|option| &option[..1]).collect();
    let prompt = format!("{question} [{}]: ", letters.join("/"));
    loop {
        let answer = read_line(&prompt)?.to_ascii_lowercase();
        let chosen = options.iter().copied().find(|option| answer == *option || answer == option[..1]);
        if let Some(option) = chosen {
            return Ok(option);
        }
        eprintln!("  please answer {}", letters.join(" or "));
    }
}

fn line_buffer() -> Zeroizing<Vec<u8>> {
    let line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    protect::lock(line.as_ptr(), MAX_LINE);
    line
}

fn push(line: &mut Vec<u8>, byte: u8) -> Result<()> {
    if line.len() == MAX_LINE {
        return Err(format!("that line is over {MAX_LINE} bytes, the longest a path or answer can be").into());
    }
    line.push(byte);
    Ok(())
}

/// Removes the last character, including all bytes of a multi-byte one.
fn pop_char(line: &mut Vec<u8>) {
    while line.pop().is_some_and(|byte| byte & 0xC0 == 0x80) {}
}

/// Trims the line in place and turns it into a string without copying it.
fn finish(mut line: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    let end = line.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(0, |i| i + 1);
    line.truncate(end);
    let start = line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(end);
    line.drain(..start);
    String::from_utf8(std::mem::take(&mut *line)).map(Zeroizing::new).map_err(|e| {
        e.into_bytes().zeroize();
        Error::from("that isn't valid UTF-8 text. If it's a file name with unusual characters, rename the file and try again")
    })
}

/// Reads one byte from `fd`, or `None` at end of input. Fails if the user asks
/// to stop while it waits.
fn read_byte(fd: libc::c_int) -> Result<Option<u8>> {
    let mut byte = 0u8;
    loop {
        // A stop requested between prompts shouldn't wait for another key.
        protect::check()?;
        // SAFETY: reads at most one byte into a valid local.
        match unsafe { libc::read(fd, std::ptr::from_mut(&mut byte).cast(), 1) } {
            1 => return Ok(Some(byte)),
            0 => return Ok(None),
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(format!("cannot read input: {err}").into());
                }
                protect::check()?;
            }
        }
    }
}

/// Discards the rest of an escape sequence such as an arrow key.
fn skip_escape_sequence(fd: libc::c_int) -> Result<()> {
    if let Some(b'[' | b'O') = read_byte(fd)? {
        while let Some(byte) = read_byte(fd)? {
            if (0x40..=0x7e).contains(&byte) {
                break;
            }
        }
    }
    Ok(())
}

fn wait_for_enter(fd: libc::c_int) -> Result<()> {
    loop {
        match read_byte(fd)? {
            Some(b'\r' | b'\n') => return Ok(()),
            Some(0x03) => {
                protect::request_stop();
                return Err(Error::Interrupted);
            }
            None => return Err("the terminal closed before Enter was pressed".into()),
            Some(_) => {}
        }
    }
}

/// Turns off echo, line editing and signal keys on a terminal until dropped.
pub struct RawMode {
    fd: libc::c_int,
    saved: libc::termios,
}

impl RawMode {
    pub fn enter(fd: libc::c_int) -> Result<Self> {
        // SAFETY: termios is plain data, filled in by tcgetattr before use.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return Err(format!("cannot configure terminal: {}", io::Error::last_os_error()).into());
            }
            let mut raw = saved;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return Err(format!("cannot configure terminal: {}", io::Error::last_os_error()).into());
            }
            Ok(Self { fd, saved })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restores the settings read in `enter` on the same descriptor.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_direction_characters() {
        assert_eq!(safe("report.pdf"), "report.pdf");
        assert_eq!(safe("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(safe("x\ny"), "x\\u{a}y");
        assert_eq!(safe("evil\u{202E}fdp.exe"), "evil\\u{202e}fdp.exe");
        assert_eq!(safe("café"), "café");
    }

    #[test]
    fn trims_without_copying() {
        let mut line = line_buffer();
        line.extend_from_slice(b"  abc def \t");
        let ptr = line.as_ptr();
        let done = finish(line).unwrap();
        assert_eq!(done.as_str(), "abc def");
        assert_eq!(done.as_ptr(), ptr);
    }

    #[test]
    fn backspace_removes_whole_characters() {
        let mut line = "aé".as_bytes().to_vec();
        pop_char(&mut line);
        assert_eq!(line, b"a");
        pop_char(&mut line);
        pop_char(&mut line);
        assert!(line.is_empty());
    }
}
