//! The home screen `encryptor` shows when run on its own in a terminal: the
//! name in large letters, the version, the help, and keys to encrypt or
//! decrypt a file. It is drawn on the alternate screen, like `less`, so the
//! terminal is left as it was. In a session (see `session`), the run is on
//! the alternate screen already.

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::term::RawMode;
use crate::{protect, session};

/// A padlock beside the name, as figlet's standard font draws it.
pub const ART: [&str; 7] = [
    r"   .----.",
    r"  / .--. \                                      _",
    r"  | |  | |      ___ _ __   ___ _ __ _   _ _ __ | |_ ___  _ __",
    r" .'-'--'-'.    / _ \ '_ \ / __| '__| | | | '_ \| __/ _ \| '__|",
    r" |  (  )  |   |  __/ | | | (__| |  | |_| | |_) | || (_) | |",
    r" |   ||   |    \___|_| |_|\___|_|   \__, | .__/ \__\___/|_|",
    r" '--------'                         |___/|_|",
];

const KEYS: &str = " e encrypt a file   d decrypt a file   q quit";

/// What was chosen on the home screen.
pub enum Choice {
    Encrypt,
    Decrypt,
    Quit,
}

/// Whether the home screen can be shown: typing comes from a terminal, and
/// output goes to one that can draw it.
pub fn available() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    io::stdin().is_terminal() && io::stdout().is_terminal() && !term.is_empty() && term != "dumb"
}

/// Shows the home screen until a key chooses what to do.
pub fn show(usage: &str, version: &str) -> Result<Choice> {
    let color = std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
    let lines = content(usage, version);
    let _raw = RawMode::enter(libc::STDIN_FILENO)?;
    let _screen = Screen::enter()?;

    let mut top = 0;
    let mut shown = None;
    loop {
        protect::check()?;
        // Redrawn when scrolled, and when the window changes size.
        let (rows, cols) = terminal_size();
        if shown != Some((top, rows, cols)) {
            write(&frame(&lines, top, rows, cols, color))?;
            shown = Some((top, rows, cols));
        }
        let Some(key) = read_key(&mut next_byte)? else { continue };
        let body = body_rows(rows);
        top = match key {
            Key::Encrypt => return Ok(Choice::Encrypt),
            Key::Decrypt => return Ok(Choice::Decrypt),
            Key::Quit => return Ok(Choice::Quit),
            Key::Up => top.saturating_sub(1),
            Key::Down => top + 1,
            Key::PageUp => top.saturating_sub(body),
            Key::PageDown => top + body,
            Key::Home => 0,
            Key::End => lines.len(),
            Key::Other => top,
        }
        .min(lines.len().saturating_sub(body));
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Art,
    Title,
    Plain,
}

struct Line {
    text: String,
    style: Style,
}

/// Everything on the home screen, top to bottom, with a margin on the left.
fn content(usage: &str, version: &str) -> Vec<Line> {
    let line = |text: &str, style| Line { text: format!("  {text}"), style };
    let mut lines: Vec<Line> = ART.iter().map(|art| line(art, Style::Art)).collect();
    lines.push(line("", Style::Plain));
    lines.push(line(version, Style::Title));
    lines.push(line("", Style::Plain));
    lines.extend(usage.lines().map(|text| line(text, Style::Plain)));
    lines
}

/// Rows for the content, above the key bar.
fn body_rows(rows: usize) -> usize {
    rows.saturating_sub(1).max(1)
}

/// The whole screen as one write: the content from line `top`, cut to the
/// width, then the key bar on the last row, with where the view is when not
/// everything fits.
fn frame(lines: &[Line], top: usize, rows: usize, cols: usize, color: bool) -> String {
    let body = body_rows(rows);
    let mut out = String::from("\x1b[H");
    for line in lines.iter().skip(top).take(body) {
        let text: String = line.text.chars().take(cols).collect();
        match line.style {
            Style::Art if color => out.push_str(&format!("\x1b[1;36m{text}\x1b[0m")),
            Style::Art | Style::Title => out.push_str(&format!("\x1b[1m{text}\x1b[0m")),
            Style::Plain => out.push_str(&text),
        }
        out.push_str("\x1b[K\r\n");
    }
    for _ in lines.len().saturating_sub(top).min(body)..body {
        out.push_str("\x1b[K\r\n");
    }
    let position = match lines.len() > body {
        true => format!("arrows scroll  {}-{} of {} ", top + 1, (top + body).min(lines.len()), lines.len()),
        false => String::new(),
    };
    let gap = cols.saturating_sub(KEYS.len() + position.len());
    let bar: String = format!("{KEYS}{}{position}", " ".repeat(gap)).chars().take(cols).collect();
    out.push_str(&format!("\x1b[7m{bar}\x1b[0m\x1b[K"));
    out
}

#[derive(Debug, PartialEq)]
enum Key {
    Encrypt,
    Decrypt,
    Quit,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Other,
}

/// Decodes one key from the bytes `next` gives, waiting up to the time it's
/// given for each. `None` if nothing was pressed in time, so the screen can
/// check whether the window was resized.
fn read_key(next: &mut impl FnMut(Duration) -> Result<Option<u8>>) -> Result<Option<Key>> {
    let Some(byte) = next(Duration::from_millis(250))? else { return Ok(None) };
    Ok(Some(match byte {
        b'e' | b'E' => Key::Encrypt,
        b'd' | b'D' => Key::Decrypt,
        // q, Ctrl-C and Ctrl-D.
        b'q' | b'Q' | 0x03 | 0x04 => Key::Quit,
        b'k' => Key::Up,
        b'j' => Key::Down,
        b'b' => Key::PageUp,
        b' ' => Key::PageDown,
        b'g' => Key::Home,
        b'G' => Key::End,
        0x1b => escape_sequence(next)?,
        _ => Key::Other,
    }))
}

/// The rest of a key that starts with Escape. Arrows and paging keys send a
/// sequence straight away; Escape on its own, with nothing after it, quits.
fn escape_sequence(next: &mut impl FnMut(Duration) -> Result<Option<u8>>) -> Result<Key> {
    let soon = Duration::from_millis(50);
    match next(soon)? {
        None => return Ok(Key::Quit),
        Some(b'[' | b'O') => {}
        Some(_) => return Ok(Key::Other),
    }
    let mut number = 0u32;
    loop {
        return Ok(match next(soon)? {
            Some(digit @ b'0'..=b'9') => {
                number = number.saturating_mul(10).saturating_add(u32::from(digit - b'0'));
                continue;
            }
            Some(b'A') => Key::Up,
            Some(b'B') => Key::Down,
            Some(b'H') => Key::Home,
            Some(b'F') => Key::End,
            Some(b'~') => match number {
                5 => Key::PageUp,
                6 => Key::PageDown,
                1 | 7 => Key::Home,
                4 | 8 => Key::End,
                _ => Key::Other,
            },
            // The end of a sequence this screen has no use for.
            Some(0x40..=0x7e) | None => Key::Other,
            // Separators and modifiers, as in Ctrl+Up.
            Some(_) => continue,
        });
    }
}

/// The next byte typed, waiting at most `wait`. End of input reads as Ctrl-D.
fn next_byte(wait: Duration) -> Result<Option<u8>> {
    let mut stdin = libc::pollfd { fd: libc::STDIN_FILENO, events: libc::POLLIN, revents: 0 };
    let millis = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: polls one valid descriptor.
    let ready = unsafe { libc::poll(&mut stdin, 1, millis) };
    if ready == 0 {
        return Ok(None);
    }
    let mut byte = 0u8;
    // SAFETY: reads at most one byte into a valid local.
    let got = if ready > 0 { unsafe { libc::read(libc::STDIN_FILENO, (&raw mut byte).cast(), 1) } } else { -1 };
    match got {
        1 => Ok(Some(byte)),
        0 => Ok(Some(0x04)),
        _ => {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                protect::check()?;
                return Ok(None);
            }
            Err(Error::from(format!("cannot read input: {e}")))
        }
    }
}

/// Rows and columns of the terminal, or the classic 24 by 80 if unknown.
fn terminal_size() -> (usize, usize) {
    // SAFETY: winsize is plain data, filled in by the ioctl.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: asks the terminal on standard output for its size.
    let known = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    match known && size.ws_row > 0 && size.ws_col > 0 {
        true => (usize::from(size.ws_row), usize::from(size.ws_col)),
        false => (24, 80),
    }
}

fn write(text: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Error::from(format!("cannot write to terminal: {e}")))
}

/// The alternate screen with the cursor hidden, until dropped, even on an
/// error or Ctrl-C. In a session, the run is already on the alternate
/// screen, which is left to the session.
struct Screen;

impl Screen {
    fn enter() -> Result<Self> {
        match session::active() {
            true => write("\x1b[?25l\x1b[2J")?,
            false => write("\x1b[?1049h\x1b[?25l\x1b[2J")?,
        }
        Ok(Self)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = match session::active() {
            true => write("\x1b[2J\x1b[?25h"),
            false => write("\x1b[2J\x1b[?25h\x1b[?1049l"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a frame shows, without the escape sequences that style it.
    fn visible(frame: &str) -> Vec<String> {
        let mut plain = String::new();
        let mut chars = frame.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else if c != '\r' {
                plain.push(c);
            }
        }
        plain.split('\n').map(str::to_string).collect()
    }

    fn keys(bytes: &[u8]) -> Option<Key> {
        let mut bytes = bytes.iter().copied();
        read_key(&mut |_| Ok(bytes.next())).ok().flatten()
    }

    #[test]
    fn fits_an_80_column_terminal() {
        for line in content("", "encryptor 9.9.9") {
            assert!(line.text.len() <= 80, "{:?} is {} wide", line.text, line.text.len());
            assert!(line.text.is_ascii());
        }
    }

    #[test]
    fn shows_the_art_version_help_and_keys() {
        let lines = content("USAGE:\n    encrypt FILE", "encryptor 9.9.9");
        let screen = visible(&frame(&lines, 0, 30, 80, true));
        assert_eq!(screen.len(), 30, "one row for each line of the terminal");
        assert!(screen[2].contains("___ _ __   ___"), "{:?}", screen[2]);
        assert!(screen.iter().any(|row| row.trim() == "encryptor 9.9.9"));
        assert!(screen.iter().any(|row| row.trim() == "encrypt FILE"));
        assert!(screen[29].starts_with(" e encrypt a file   d decrypt a file   q quit"));
        assert!(!screen[29].contains("of"), "everything fits, so no position");
    }

    #[test]
    fn scrolls_and_cuts_to_a_small_terminal() {
        let usage: String = (1..=40).map(|n| format!("line {n}\n")).collect();
        let lines = content(&usage, "v");
        let screen = visible(&frame(&lines, 10, 12, 30, false));
        assert_eq!(screen.len(), 12);
        assert!(screen.iter().all(|row| row.chars().count() <= 30), "{screen:?}");
        assert_eq!(screen[0].trim(), "line 1");
        assert!(screen[11].starts_with(" e encrypt a file"), "{:?}", screen[11]);
        assert!(visible(&frame(&lines, 10, 12, 80, false))[11].ends_with(&format!("11-21 of {} ", lines.len())));
    }

    #[test]
    fn reads_keys_and_their_escape_sequences() {
        assert_eq!(keys(b"e"), Some(Key::Encrypt));
        assert_eq!(keys(b"D"), Some(Key::Decrypt));
        assert_eq!(keys(b"q"), Some(Key::Quit));
        assert_eq!(keys(&[0x03]), Some(Key::Quit));
        assert_eq!(keys(b"\x1b[A"), Some(Key::Up));
        assert_eq!(keys(b"\x1bOB"), Some(Key::Down));
        assert_eq!(keys(b"\x1b[5~"), Some(Key::PageUp));
        assert_eq!(keys(b"\x1b[6~"), Some(Key::PageDown));
        assert_eq!(keys(b"\x1b[1;5A"), Some(Key::Up));
        assert_eq!(keys(b"\x1b[H"), Some(Key::Home));
        assert_eq!(keys(b"\x1b[4~"), Some(Key::End));
        assert_eq!(keys(b"\x1b"), Some(Key::Quit), "Escape on its own");
        assert_eq!(keys(b"\x1b[Z"), Some(Key::Other));
        assert_eq!(keys(b"x"), Some(Key::Other));
        assert_eq!(keys(b""), None, "nothing pressed yet");
    }
}
