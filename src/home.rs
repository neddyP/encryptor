//! The home screen `encryptor` shows when run on its own in a terminal, and
//! for --help: the name in large letters, the text in home.txt, and keys to
//! encrypt, decrypt or view a file. It is drawn on the alternate screen, like
//! `less`, so the terminal is left as it was. In a session (see `session`),
//! the run is on the alternate screen already.

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::term::{self, RawMode};
use crate::{art, protect, session};

/// The home screen's text, which --help prints too without a terminal. Edit
/// home.txt to change it. In it:
/// - `{version}` is replaced by the version, and its line is bold.
/// - A line ending in `:` is a heading, in bold.
/// - In a line with `-->`, what's before the arrow is bold, and the rest
///   wraps to start under the text after the arrow.
/// - A tab is 4 columns, and other long lines wrap under their own indent.
const TEXT: &str = include_str!("home.txt");

const ARROW: &str = "-->";
const TAB: &str = "    ";
/// Space on the left of everything on the screen.
const MARGIN: &str = "  ";

const KEYS: &str = " e encrypt   d decrypt   v view   q quit";

/// What was chosen on the home screen.
pub enum Choice {
    Encrypt,
    Decrypt,
    View,
    Quit,
}

/// Whether the home screen can be shown: typing comes from a terminal, and
/// output goes to one that can draw it.
pub fn available() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    io::stdin().is_terminal() && io::stdout().is_terminal() && !term.is_empty() && term != "dumb"
}

/// The text as --help prints it without a terminal: unstyled, and wrapped to
/// 80 columns.
pub fn plain() -> String {
    layout(TEXT, env!("CARGO_PKG_VERSION"), 80).into_iter().map(|line| line.text + "\n").collect()
}

/// Shows the home screen until a key chooses what to do.
pub fn show() -> Result<Choice> {
    let look = art::Look::detect();
    let _raw = RawMode::enter(libc::STDIN_FILENO)?;
    let _screen = Screen::enter()?;

    let mut lines = Vec::new();
    let mut laid_out = None;
    let mut top = 0;
    let mut shown = None;
    loop {
        protect::check()?;
        // Redrawn when scrolled, and when the window changes size, and laid
        // out again when it changes width, which the art depends on. The
        // classic 24 by 80 if the terminal doesn't say.
        let (rows, cols) = term::size(libc::STDOUT_FILENO).unwrap_or((24, 80));
        if laid_out != Some(cols) {
            lines = content(TEXT, env!("CARGO_PKG_VERSION"), cols, look);
            laid_out = Some(cols);
        }
        if shown != Some((top, rows, cols)) {
            write(&frame(&lines, top, rows, cols))?;
            shown = Some((top, rows, cols));
        }
        let Some(key) = read_key(&mut |wait| term::poll_byte(libc::STDIN_FILENO, wait))? else { continue };
        let body = body_rows(rows);
        top = match key {
            Key::Encrypt => return Ok(Choice::Encrypt),
            Key::Decrypt => return Ok(Choice::Decrypt),
            Key::View => return Ok(Choice::View),
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum Style {
    /// Already coloured, and laid out for the width.
    Art,
    Bold,
    /// Bold for this many columns, then plain.
    Entry(usize),
    Plain,
}

#[derive(Debug)]
struct Line {
    text: String,
    style: Style,
}

/// Everything on the home screen, top to bottom, with a margin on the left,
/// for a window `cols` wide that can draw as `look` says.
fn content(text: &str, version: &str, cols: usize, look: art::Look) -> Vec<Line> {
    let width = cols.saturating_sub(MARGIN.len());
    let art = art::rows(width, look.utf8);
    let mut lines: Vec<Line> = art
        .iter()
        .enumerate()
        .map(|(i, row)| Line { text: format!("{MARGIN}{}", art::paint(row, i, art.len(), look.colors)), style: Style::Art })
        .collect();
    if !art.is_empty() {
        lines.push(Line { text: String::new(), style: Style::Plain });
    }
    lines.extend(layout(text, version, width).into_iter().map(|line| Line {
        text: format!("{MARGIN}{}", line.text),
        style: match line.style {
            Style::Entry(bold) => Style::Entry(bold + MARGIN.len()),
            style => style,
        },
    }));
    lines
}

/// `text` laid out for `width` columns: each line styled and wrapped as
/// TEXT's comment says.
fn layout(text: &str, version: &str, width: usize) -> Vec<Line> {
    let mut lines = Vec::new();
    for raw in text.lines() {
        let expanded = raw.replace("{version}", version).replace('\t', TAB);
        let line = expanded.trim_end();
        let arrow = line.find(ARROW);
        let style = match arrow {
            _ if raw.contains("{version}") => Style::Bold,
            None if line.ends_with(':') => Style::Bold,
            Some(at) => Style::Entry(line[..at].trim_end().chars().count()),
            None => Style::Plain,
        };
        for (n, text) in wrap(line, width).into_iter().enumerate() {
            let style = match style {
                Style::Entry(_) if n > 0 => Style::Plain,
                style => style,
            };
            lines.push(Line { text, style });
        }
    }
    lines
}

/// `line` cut at spaces into lines `width` columns wide or less. Lines after
/// the first start under the text after an arrow, or else under the line's
/// own indent; or, if that's past half the width, 4 columns in from it. A
/// word wider than `width` gets a line of its own, and is cut when drawn.
fn wrap(line: &str, width: usize) -> Vec<String> {
    let columns = |text: &str| text.chars().count();
    let indent = columns(line) - columns(line.trim_start());
    let hang = match line.find(ARROW) {
        Some(at) => {
            let after = &line[at + ARROW.len()..];
            columns(&line[..at + ARROW.len()]) + columns(after) - columns(after.trim_start())
        }
        None => indent,
    };
    let hang = if hang * 2 > width { (indent + TAB.len()).min(width / 2) } else { hang };

    let mut lines = Vec::new();
    let mut current = String::new();
    let mut used = 0;
    let mut words = 0;
    let mut rest = line;
    while let Some(start) = rest.find(|c: char| c != ' ') {
        let end = rest[start..].find(' ').map_or(rest.len(), |n| start + n);
        let (gap, word) = (&rest[..start], &rest[start..end]);
        rest = &rest[end..];
        words += 1;
        if words > 1 && used + columns(gap) + columns(word) > width {
            lines.push(std::mem::replace(&mut current, " ".repeat(hang)));
            used = hang;
        } else {
            current.push_str(gap);
            used += columns(gap);
        }
        current.push_str(word);
        used += columns(word);
    }
    lines.push(current);
    lines
}

/// Rows for the content, above the key bar.
fn body_rows(rows: usize) -> usize {
    rows.saturating_sub(1).max(1)
}

/// The whole screen as one write: the content from line `top`, cut to the
/// width, then the key bar on the last row, with where the view is when not
/// everything fits.
fn frame(lines: &[Line], top: usize, rows: usize, cols: usize) -> String {
    let body = body_rows(rows);
    let mut out = String::from("\x1b[H");
    for line in lines.iter().skip(top).take(body) {
        let text: String = line.text.chars().take(cols).collect();
        match line.style {
            // Laid out to fit already, and its colours aren't columns.
            Style::Art => out.push_str(&line.text),
            Style::Bold => out.push_str(&format!("\x1b[1m{text}\x1b[0m")),
            Style::Entry(bold) => {
                let at = text.char_indices().nth(bold).map_or(text.len(), |(at, _)| at);
                out.push_str(&format!("\x1b[1m{}\x1b[0m{}", &text[..at], &text[at..]));
            }
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
    View,
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
    let Some(key) = term::read_key(next)? else { return Ok(None) };
    Ok(Some(match key {
        term::Key::Byte(b'e' | b'E') => Key::Encrypt,
        term::Key::Byte(b'd' | b'D') => Key::Decrypt,
        term::Key::Byte(b'v' | b'V') => Key::View,
        // q, Escape on its own, Ctrl-C and Ctrl-D.
        term::Key::Byte(b'q' | b'Q' | 0x03 | 0x04) | term::Key::Escape => Key::Quit,
        term::Key::Byte(b'k') | term::Key::Up => Key::Up,
        term::Key::Byte(b'j') | term::Key::Down => Key::Down,
        term::Key::Byte(b'b') | term::Key::PageUp => Key::PageUp,
        term::Key::Byte(b' ') | term::Key::PageDown => Key::PageDown,
        term::Key::Byte(b'g') | term::Key::Home => Key::Home,
        term::Key::Byte(b'G') | term::Key::End => Key::End,
        _ => Key::Other,
    }))
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

    const ASCII: art::Look = art::Look { utf8: false, colors: art::Colors::None };

    #[test]
    fn fits_the_text_to_an_80_column_terminal() {
        for utf8 in [true, false] {
            let look = art::Look { utf8, colors: art::Colors::Rich };
            for line in content(TEXT, "9.9.9", 80, look) {
                let shown = &visible(&line.text)[0];
                assert!(shown.chars().count() <= 80, "{shown:?} is {} wide", shown.chars().count());
                assert!(utf8 || shown.is_ascii());
            }
        }
        assert!(plain().lines().all(|line| line.chars().count() <= 80), "{}", plain());
        assert!(!plain().contains('\t') && !plain().contains("{version}"));
    }

    #[test]
    fn shows_the_art_text_and_keys() {
        let lines = content(TEXT, "9.9.9", 80, ASCII);
        let screen = visible(&frame(&lines, 0, 30, 80));
        assert_eq!(screen.len(), 30, "one row for each line of the terminal");
        assert!(screen[2].contains("___ _ __   ___"), "{:?}", screen[2]);
        assert!(screen.iter().any(|row| row.trim() == "Welcome to Encryptor 9.9.9!"), "{screen:?}");
        assert!(screen[29].starts_with(" e encrypt   d decrypt   v view   q quit"));
        assert!(screen[29].contains("of"), "the text doesn't all fit, so where the view is");

        let utf8 = art::Look { utf8: true, ..ASCII };
        let block = content("", "v", 81, utf8);
        assert!(visible(&block[3].text)[0].contains("██║   .'-'--'-'. ██████╔╝"), "the padlock in place of the O");
        assert!(visible(&content("", "v", 80, utf8)[2].text)[0].contains("___ _ __   ___"), "ASCII at 80 columns");
        assert!(content("{version}", "v", 40, ASCII)[0].text.contains('v'), "no art in a narrow window");
    }

    #[test]
    fn styles_the_title_headings_and_commands() {
        let lines = layout("\tWelcome {version}!\n\tCommands:\n\t\tencrypt a.pdf  -->  encrypts it\nplain", "9.9.9", 80);
        let styles: Vec<Style> = lines.iter().map(|line| line.style).collect();
        assert_eq!(styles, [Style::Bold, Style::Bold, Style::Entry(21), Style::Plain]);
        assert_eq!(lines[0].text, "    Welcome 9.9.9!", "a tab is 4 columns");
        let drawn = frame(&content("\t\tencrypt a.pdf  -->  encrypts it", "v", 50, ASCII), 0, 3, 50);
        assert!(drawn.contains("\x1b[1m          encrypt a.pdf\x1b[0m  -->  encrypts it"), "{drawn:?}");
    }

    #[test]
    fn wraps_under_the_arrow_or_the_indent() {
        let entry = wrap("    -q, --quiet  -->  doesn't print the encryption or decryption summary", 50);
        assert_eq!(entry, [
            "    -q, --quiet  -->  doesn't print the encryption",
            "                      or decryption summary",
        ]);
        let prose = wrap("    We use chunking to handle files of any size, and folders in one go!", 40);
        assert_eq!(prose, ["    We use chunking to handle files of", "    any size, and folders in one go!"]);
        let deep = wrap("  -k, --key-file ~/PATH/example.pdf.key  -->  decrypts with its key", 50);
        assert_eq!(deep[1], "      decrypts with its key", "past half the width, 4 in from the indent");
        assert_eq!(wrap("", 80), [""]);
        assert_eq!(wrap("    ==========", 6), ["    =========="], "a word too wide for any line");
    }

    #[test]
    fn scrolls_and_cuts_to_a_small_terminal() {
        let usage: String = (1..=40).map(|n| format!("line {n}\n")).collect();
        let lines = content(&usage, "v", 80, ASCII);
        let screen = visible(&frame(&lines, 10, 12, 30));
        assert_eq!(screen.len(), 12);
        assert!(screen.iter().all(|row| row.chars().count() <= 30), "{screen:?}");
        assert_eq!(screen[0].trim(), "line 3", "7 rows of art and a blank, then the text");
        assert!(screen[11].starts_with(" e encrypt"), "{:?}", screen[11]);
        assert!(visible(&frame(&lines, 10, 12, 80))[11].ends_with(&format!("11-21 of {} ", lines.len())));
    }

    #[test]
    fn reads_keys_and_their_escape_sequences() {
        assert_eq!(keys(b"e"), Some(Key::Encrypt));
        assert_eq!(keys(b"D"), Some(Key::Decrypt));
        assert_eq!(keys(b"v"), Some(Key::View));
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
