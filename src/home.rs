//! The home screen `encryptor` shows when run on its own in a terminal: the
//! name in large letters, the version, the help, and keys to encrypt or
//! decrypt a file. It's printed like any other output, so it stays in the
//! terminal's scrollback along with everything before it.

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::protect;
use crate::term::RawMode;

/// A padlock beside the name, as figlet's standard font draws it.
const ART: [&str; 7] = [
    r"   .----.",
    r"  / .--. \                                      _",
    r"  | |  | |      ___ _ __   ___ _ __ _   _ _ __ | |_ ___  _ __",
    r" .'-'--'-'.    / _ \ '_ \ / __| '__| | | | '_ \| __/ _ \| '__|",
    r" |  (  )  |   |  __/ | | | (__| |  | |_| | |_) | || (_) | |",
    r" |   ||   |    \___|_| |_|\___|_|   \__, | .__/ \__\___/|_|",
    r" '--------'                         |___/|_|",
];

const KEYS: &str = " e encrypt a file   d decrypt a file   q quit ";

/// Left margin for everything above the keys.
const MARGIN: &str = "  ";

/// What was chosen on the home screen.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Choice {
    Encrypt,
    Decrypt,
    Quit,
}

impl Choice {
    fn word(self) -> &'static str {
        match self {
            Choice::Encrypt => "encrypt",
            Choice::Decrypt => "decrypt",
            Choice::Quit => "quit",
        }
    }
}

/// Whether the home screen can be shown: typing comes from a terminal, and
/// output goes to one that can draw it.
pub fn available() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    io::stdin().is_terminal() && io::stdout().is_terminal() && !term.is_empty() && term != "dumb"
}

/// Prints the home screen, then waits for a key that chooses what to do.
pub fn show(usage: &str, version: &str) -> Result<Choice> {
    let color = std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
    write(&render(usage, version, terminal_columns(), color))?;
    let choice = {
        let _raw = RawMode::enter(libc::STDIN_FILENO)?;
        loop {
            protect::check()?;
            match read_key(&mut next_byte)? {
                Some(Key::Encrypt) => break Choice::Encrypt,
                Some(Key::Decrypt) => break Choice::Decrypt,
                Some(Key::Quit) => break Choice::Quit,
                Some(Key::Other) | None => {}
            }
        }
    };
    // What was chosen goes after the keys, so the scrollback shows it.
    write(&format!("{}\n", choice.word()))?;
    Ok(choice)
}

/// The home screen as printed: the art when the terminal is wide enough for
/// it, the version, the help, and the keys, which are left without a line
/// break for the choice to follow.
fn render(usage: &str, version: &str, cols: usize, color: bool) -> String {
    let mut out = String::from("\n");
    let art_width = MARGIN.len() + ART.iter().map(|line| line.len()).max().unwrap_or(0);
    if cols >= art_width {
        let style = if color { "\x1b[1;36m" } else { "\x1b[1m" };
        for line in ART {
            out.push_str(&format!("{MARGIN}{style}{line}\x1b[0m\n"));
        }
        out.push('\n');
    }
    out.push_str(&format!("{MARGIN}\x1b[1m{version}\x1b[0m\n\n"));
    for line in usage.lines() {
        match line.is_empty() {
            true => out.push('\n'),
            false => out.push_str(&format!("{MARGIN}{line}\n")),
        }
    }
    out.push_str(&format!("\n\x1b[7m{KEYS}\x1b[0m "));
    out
}

#[derive(Debug, PartialEq)]
enum Key {
    Encrypt,
    Decrypt,
    Quit,
    Other,
}

/// Decodes one key from the bytes `next` gives, waiting up to the time it's
/// given for each. `None` if nothing was pressed in time, so an interrupt can
/// be noticed.
fn read_key(next: &mut impl FnMut(Duration) -> Result<Option<u8>>) -> Result<Option<Key>> {
    let Some(byte) = next(Duration::from_millis(250))? else { return Ok(None) };
    Ok(Some(match byte {
        b'e' | b'E' => Key::Encrypt,
        b'd' | b'D' => Key::Decrypt,
        // q, Ctrl-C and Ctrl-D.
        b'q' | b'Q' | 0x03 | 0x04 => Key::Quit,
        0x1b => escape_sequence(next)?,
        _ => Key::Other,
    }))
}

/// The rest of a key that starts with Escape. Keys like the arrows send a
/// sequence straight away, which is read to its end and ignored; Escape on its
/// own, with nothing after it, quits.
fn escape_sequence(next: &mut impl FnMut(Duration) -> Result<Option<u8>>) -> Result<Key> {
    let soon = Duration::from_millis(50);
    match next(soon)? {
        None => return Ok(Key::Quit),
        Some(b'[' | b'O') => {}
        Some(_) => return Ok(Key::Other),
    }
    // Parameters and separators, up to the final byte, as in Ctrl+Up.
    while let Some(byte) = next(soon)? {
        if (0x40..=0x7e).contains(&byte) {
            break;
        }
    }
    Ok(Key::Other)
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

/// Columns of the terminal, or the classic 80 if unknown.
fn terminal_columns() -> usize {
    // SAFETY: winsize is plain data, filled in by the ioctl.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: asks the terminal on standard output for its size.
    let known = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    match known && size.ws_col > 0 {
        true => usize::from(size.ws_col),
        false => 80,
    }
}

fn write(text: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Error::from(format!("cannot write to terminal: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the home screen shows, line by line, without the escape sequences
    /// that style it.
    fn visible(text: &str) -> Vec<String> {
        let mut plain = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
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
        let text = render(crate::USAGE, "encryptor 9.9.9, writing file format 9", 80, true);
        for line in visible(&text) {
            assert!(line.chars().count() <= 80, "{line:?} is {} wide", line.chars().count());
            assert!(line.is_ascii());
        }
    }

    #[test]
    fn shows_the_art_version_help_and_keys() {
        let text = render("USAGE:\n    encrypt FILE", "encryptor 9.9.9", 80, true);
        let lines = visible(&text);
        assert!(lines.iter().any(|line| line.contains("___ _ __   ___")), "{lines:?}");
        assert!(lines.iter().any(|line| line.trim() == "encryptor 9.9.9"));
        assert!(lines.iter().any(|line| line.trim() == "encrypt FILE"));
        let last = lines.last().expect("a last line");
        assert_eq!(last.trim(), KEYS.trim(), "the keys come last, for the choice to follow");
        assert!(!text.ends_with('\n'));
    }

    #[test]
    fn prints_in_place_without_taking_over_the_screen() {
        let text = render("USAGE:\n    encrypt FILE", "encryptor 9.9.9", 80, true);
        for sequence in ["\x1b[?1049h", "\x1b[?47h", "\x1b[2J", "\x1b[3J", "\x1b[H", "\x1b[?25l"] {
            assert!(!text.contains(sequence), "{sequence:?} would move to or clear a screen");
        }
    }

    #[test]
    fn leaves_out_the_art_when_too_narrow_for_it() {
        let lines = visible(&render("USAGE:\n    encrypt FILE", "encryptor 9.9.9", 40, false));
        assert!(!lines.iter().any(|line| line.contains("___")), "{lines:?}");
        assert!(lines.iter().any(|line| line.trim() == "encryptor 9.9.9"));
    }

    #[test]
    fn reads_keys_and_skips_escape_sequences() {
        assert_eq!(keys(b"e"), Some(Key::Encrypt));
        assert_eq!(keys(b"D"), Some(Key::Decrypt));
        assert_eq!(keys(b"q"), Some(Key::Quit));
        assert_eq!(keys(&[0x03]), Some(Key::Quit));
        assert_eq!(keys(&[0x04]), Some(Key::Quit));
        assert_eq!(keys(b"\x1b"), Some(Key::Quit), "Escape on its own");
        assert_eq!(keys(b"\x1b[A"), Some(Key::Other), "an arrow");
        assert_eq!(keys(b"\x1bOB"), Some(Key::Other));
        assert_eq!(keys(b"\x1b[1;5A"), Some(Key::Other), "Ctrl+Up");
        assert_eq!(keys(b"\x1b[5~"), Some(Key::Other), "Page Up");
        assert_eq!(keys(b"x"), Some(Key::Other));
        assert_eq!(keys(b""), None, "nothing pressed yet");
    }

    #[test]
    fn an_escape_sequence_is_read_to_its_end() {
        let mut bytes = b"\x1b[1;5Ae".iter().copied();
        let mut next = |_| Ok(bytes.next());
        assert_eq!(read_key(&mut next).ok().flatten(), Some(Key::Other));
        assert_eq!(read_key(&mut next).ok().flatten(), Some(Key::Encrypt), "the e after Ctrl+Up");
    }
}
