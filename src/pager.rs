//! Showing a decrypted file on the terminal, for `view`: on a screen of its
//! own, which keeps no scrollback, scrolled with the arrow keys and erased
//! when Enter is pressed. Like a printed key, it goes straight to the
//! terminal, never through standard output, so redirecting the output can't
//! capture it, and each screenful is built in locked memory and wiped once
//! drawn. Text is shown with its control characters made visible, so a file
//! can't move the cursor, retitle the window or reach the clipboard with
//! escape sequences of its own. Anything that isn't text is shown as a hex
//! dump.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::term::{self, Key, RawMode};
use crate::{explain, protect, session};

/// The largest file view shows, as far as its rows can count. It's held in
/// locked memory whole, so how much can be locked usually limits it first.
pub const MAX_LEN: u64 = u32::MAX as u64;

/// Columns between tab stops, as terminals set them.
const TAB: usize = 8;

const KEYS: &str = " Enter done, erases the screen   arrows, PgUp, PgDn scroll";
/// The keys in brief, for a window too narrow for them and where the view is.
const KEYS_BRIEF: &str = " Enter done";

/// Shows `contents` until Enter, q or Escape is pressed, then erases it. In
/// a session, the run's own screen is drawn again afterwards. `name`, already
/// safe to print, heads the screen. Ctrl-C returns `Interrupted`.
pub fn show(contents: &[u8], name: &str) -> Result<()> {
    if contents.len() as u64 > MAX_LEN {
        return Err(format!("{name} is too large to show: view shows files of up to {}", term::short_size(MAX_LEN)).into());
    }
    let tty = term::open_screen().map_err(|reason| Error::from(explain::cant_view_here(reason)))?;
    let mut screen = Screen::enter(tty)?;
    let fd = screen.tty.as_raw_fd();
    let (_, cols) = term::size(fd).unwrap_or((24, 80));
    let mut page = Page::new(contents, cols);
    let title = match (contents.is_empty(), &page.layout) {
        (true, _) => format!(" {name} is empty"),
        (false, Layout::Text { .. }) => format!(" {name}, decrypted in memory only"),
        (false, Layout::Hex { .. }) => format!(" {name}, decrypted in memory only, in hex as it isn't text"),
    };

    let mut top = 0;
    let mut shown = None;
    loop {
        protect::check()?;
        // Laid out and drawn again when the window changes size, keeping the
        // same place in the file at the top.
        let (rows, cols) = term::size(fd).unwrap_or((24, 80));
        if page.cols != cols {
            let offset = page.offset(top);
            page = Page::new(contents, cols);
            top = page.row_at(offset);
        }
        let body = body_rows(rows);
        top = top.min(page.rows().saturating_sub(body));
        if shown != Some((top, rows, cols)) {
            screen.draw(&frame(&page, &title, top, rows, cols)?)?;
            shown = Some((top, rows, cols));
        }
        let Some(key) = term::read_key(&mut |wait| term::poll_byte(fd, wait))? else { continue };
        top = match key {
            Key::Byte(b'\r' | b'\n' | b'q' | b'Q' | 0x04) | Key::Escape => return Ok(()),
            Key::Byte(0x03) => {
                protect::request_stop();
                return Err(Error::Interrupted);
            }
            Key::Byte(b'k') | Key::Up => top.saturating_sub(1),
            Key::Byte(b'j') | Key::Down => top + 1,
            Key::Byte(b'b') | Key::PageUp => top.saturating_sub(body),
            Key::Byte(b' ' | b'f') | Key::PageDown => top + body,
            Key::Byte(b'g') | Key::Home => 0,
            Key::Byte(b'G') | Key::End => page.rows(),
            _ => top,
        };
    }
}

/// The file laid out in rows for a width.
struct Page<'a> {
    cols: usize,
    layout: Layout<'a>,
}

enum Layout<'a> {
    /// Text, wrapped at the window's edge, with where each row starts in it.
    Text { text: &'a str, starts: Vec<u32> },
    /// Anything else, a number of bytes to a row.
    Hex { bytes: &'a [u8], per_row: usize },
}

impl<'a> Page<'a> {
    /// Text is UTF-8 without NUL bytes, which text files don't have.
    fn new(contents: &'a [u8], cols: usize) -> Self {
        let layout = match std::str::from_utf8(contents) {
            Ok(text) if !text.contains('\0') => Layout::Text { text, starts: wrap(text, cols) },
            _ => Layout::Hex { bytes: contents, per_row: if cols >= hex_width(16) { 16 } else { 8 } },
        };
        Self { cols, layout }
    }

    fn rows(&self) -> usize {
        match &self.layout {
            Layout::Text { starts, .. } => starts.len(),
            Layout::Hex { bytes, per_row } => bytes.len().div_ceil(*per_row).max(1),
        }
    }

    /// Where in the file `row` starts.
    fn offset(&self, row: usize) -> usize {
        match &self.layout {
            Layout::Text { starts, .. } => starts.get(row).map_or(0, |&start| start as usize),
            Layout::Hex { per_row, .. } => row * per_row,
        }
    }

    /// The row that holds the byte at `offset`.
    fn row_at(&self, offset: usize) -> usize {
        match &self.layout {
            Layout::Text { starts, .. } => starts.partition_point(|&start| start as usize <= offset).saturating_sub(1),
            Layout::Hex { per_row, .. } => offset / per_row,
        }
    }

    fn render(&self, row: usize, out: &mut Vec<u8>) {
        match &self.layout {
            Layout::Text { text, starts } => render_text(text, starts, row, out),
            Layout::Hex { bytes, per_row } => render_hex(bytes, *per_row, row, out),
        }
    }
}

/// Where each row of `text` starts when it's wrapped at `cols` columns: at
/// the start, after each line break, and where a line reaches the edge.
fn wrap(text: &str, cols: usize) -> Vec<u32> {
    let mut starts = vec![0];
    let mut col = 0;
    for (i, c) in text.char_indices() {
        if c == '\n' {
            // A line break at the very end doesn't start another row.
            if i + 1 < text.len() {
                starts.push((i + 1) as u32);
            }
            col = 0;
            continue;
        }
        if col > 0 && col + width(c, col) > cols {
            starts.push(i as u32);
            col = 0;
        }
        col += width(c, col);
    }
    starts
}

/// Columns `c` takes when shown at column `col`. Wide characters are
/// recognised in the main ranges only, and anything takes at least one
/// column, so a row never holds more than four bytes a column. A row that
/// still turns out too wide is cut off at the edge, not wrapped.
fn width(c: char, col: usize) -> usize {
    match c {
        '\t' => TAB - col % TAB,
        c if caret(c).is_some() => 2,
        c if escaped(c) => c.escape_unicode().count(),
        c if wide(c) => 2,
        _ => 1,
    }
}

/// The letter a C0 control character or DEL is shown with after ^, as
/// `cat -v` shows them: ^[ for Escape, ^M for a carriage return.
fn caret(c: char) -> Option<u8> {
    match c {
        '\0'..='\x1f' | '\x7f' => Some((c as u8) ^ 0x40),
        _ => None,
    }
}

/// Other characters that control the terminal, or reorder the text around
/// them, shown escaped instead, as in \u{9b}.
fn escaped(c: char) -> bool {
    c.is_control() || term::is_direction_control(c)
}

/// East Asian wide and fullwidth characters, and emoji.
fn wide(c: char) -> bool {
    matches!(
        c as u32,
        0x1100..=0x115F
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA000..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F900..=0x1F9FF
            | 0x20000..=0x2FFFD
            | 0x30000..=0x3FFFD
    )
}

fn render_text(text: &str, starts: &[u32], row: usize, out: &mut Vec<u8>) {
    let start = starts.get(row).map_or(text.len(), |&start| start as usize);
    let end = starts.get(row + 1).map_or(text.len(), |&next| next as usize);
    // Rows start on characters, but a slip here mustn't panic, as the panic
    // message would quote the text.
    let mut line = text.get(start..end).unwrap_or_default();
    // The line break that ends the row, with the carriage return before it
    // in Windows text.
    if let Some(rest) = line.strip_suffix('\n') {
        line = rest.strip_suffix('\r').unwrap_or(rest);
    }
    let mut col = 0;
    for (i, c) in line.char_indices() {
        let columns = width(c, col);
        if c == '\t' {
            out.extend(std::iter::repeat_n(b' ', columns));
        } else if let Some(letter) = caret(c) {
            out.extend_from_slice(&[b'^', letter]);
        } else if escaped(c) {
            out.extend(c.escape_unicode().map(|e| e as u8));
        } else {
            // Straight from the file, not through a copy.
            out.extend_from_slice(&line.as_bytes()[i..i + c.len_utf8()]);
        }
        col += columns;
    }
}

/// Columns a hex dump row of `per_row` bytes takes: the offset, the bytes in
/// groups of eight, then the bytes as text.
fn hex_width(per_row: usize) -> usize {
    10 + per_row * 3 + (per_row / 8 - 1) + 1 + per_row + 1
}

fn render_hex(bytes: &[u8], per_row: usize, row: usize, out: &mut Vec<u8>) {
    let start = (row * per_row).min(bytes.len());
    let chunk = &bytes[start..(start + per_row).min(bytes.len())];
    let _ = write!(out, "{start:08x}  ");
    for i in 0..per_row {
        match chunk.get(i) {
            Some(byte) => {
                let _ = write!(out, "{byte:02x} ");
            }
            None => out.extend_from_slice(b"   "),
        }
        if i % 8 == 7 && i + 1 < per_row {
            out.push(b' ');
        }
    }
    out.push(b'|');
    out.extend(chunk.iter().map(|&byte| if (0x20..0x7f).contains(&byte) { byte } else { b'.' }));
    out.push(b'|');
}

/// Rows for the file, between the line naming it and the key bar.
fn body_rows(rows: usize) -> usize {
    rows.saturating_sub(2).max(1)
}

/// The whole screen as one write, built in locked memory that's wiped when
/// it's dropped: `title`, the rows from `top`, then the keys and where the
/// view is. Each row is erased just before it's written. Fails, before any
/// of the file is put in it, if the memory couldn't be locked.
fn frame(page: &Page, title: &str, top: usize, rows: usize, cols: usize) -> Result<Zeroizing<Vec<u8>>> {
    let body = body_rows(rows);
    let mut out = Zeroizing::new(Vec::with_capacity(frame_capacity(rows, cols)));
    protect::lock(out.as_ptr(), out.capacity());
    protect::check_locked()?;
    bar(&mut out, 1, title, "", cols);
    for (i, row) in (top..top + body).enumerate() {
        let _ = write!(out, "\x1b[{};1H\x1b[2K", i + 2);
        if row < page.rows() {
            page.render(row, &mut out);
        }
    }
    let total = page.rows();
    let position = format!("{}-{} of {total} rows ", top + 1, (top + body).min(total));
    let keys = if KEYS.len() + position.len() <= cols { KEYS } else { KEYS_BRIEF };
    bar(&mut out, body + 2, keys, &position, cols);
    Ok(out)
}

/// The most a frame can take: up to four bytes a column, and room for the
/// escape sequences. Allocated up front, it never grows and leaves a copy
/// behind.
fn frame_capacity(rows: usize, cols: usize) -> usize {
    (body_rows(rows) + 2) * (cols * 4 + 24) + 64
}

/// A row in reverse video across the whole width, `left` at its start and
/// `right` at its end, when there's room for it.
fn bar(out: &mut Vec<u8>, row: usize, left: &str, right: &str, cols: usize) {
    let used = left.chars().count() + right.chars().count();
    let right = if used <= cols { right } else { "" };
    let gap = cols.saturating_sub(left.chars().count() + right.chars().count());
    let line: String = format!("{left}{}{right}", " ".repeat(gap)).chars().take(cols).collect();
    let _ = write!(out, "\x1b[{row};1H\x1b[2K\x1b[7m{line}\x1b[0m");
}

/// The screen the file is shown on, until dropped, even on an error or
/// Ctrl-C: then it's erased, and in a session the run's own screen is drawn
/// again. Erasing the screen is enough, as the alternate screen keeps no
/// scrollback; erasing scrollback as well (ESC [3J) could reach the window's
/// own history.
struct Screen {
    // Declared first, so the terminal's settings are put back before it's
    // closed.
    _raw: RawMode,
    tty: File,
    in_session: bool,
}

impl Screen {
    fn enter(tty: File) -> Result<Self> {
        let raw = RawMode::enter(tty.as_raw_fd())?;
        let in_session = session::active();
        let mut screen = Self { _raw: raw, tty, in_session };
        let _ = io::stdout().flush();
        // The cursor hidden, and rows that turn out too wide cut off at the
        // edge, rather than wrapped by the terminal onto the next.
        let open: &[u8] = match in_session {
            true => b"\x1b[?25l\x1b[?7l\x1b[H\x1b[2J",
            false => b"\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[H\x1b[2J",
        };
        screen.draw(open)?;
        Ok(screen)
    }

    fn draw(&mut self, bytes: &[u8]) -> Result<()> {
        self.tty
            .write_all(bytes)
            .and_then(|()| self.tty.flush())
            .map_err(|e| Error::from(format!("cannot write to terminal: {e}")))
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let close: &[u8] = match self.in_session {
            true => b"\x1b[H\x1b[2J\x1b[?7h\x1b[?25h",
            false => b"\x1b[H\x1b[2J\x1b[?7h\x1b[?25h\x1b[?1049l",
        };
        let _ = self.tty.write_all(close);
        if self.in_session {
            session::header();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(page: &Page, row: usize) -> String {
        let mut out = Vec::new();
        page.render(row, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn wraps_lines_at_the_edge_and_after_line_breaks() {
        let page = Page::new(b"ab\ncdefgh\n", 4);
        assert!(matches!(&page.layout, Layout::Text { starts, .. } if *starts == [0, 3, 7]));
        assert_eq!([rendered(&page, 0), rendered(&page, 1), rendered(&page, 2)], ["ab", "cdef", "gh"]);
        // Tabs reach the next stop; wide characters take two columns.
        assert_eq!(rendered(&Page::new(b"a\tb", 80), 0), "a       b");
        assert_eq!(Page::new("\u{4e2d}\u{6587}x".as_bytes(), 4).rows(), 2);
        assert_eq!(Page::new(b"", 80).rows(), 1);
    }

    #[test]
    fn shows_control_characters_instead_of_obeying_them() {
        // Clearing the screen, a bell, an OSC 52 clipboard write and a
        // direction override that would reorder the text after it.
        let text = "a\x1b[2Jb\x07\x1b]52;c;aGk=\x07\r\n\u{202e}evil\u{9b}31m\r\n";
        let page = Page::new(text.as_bytes(), 80);
        assert_eq!(rendered(&page, 0), "a^[[2Jb^G^[]52;c;aGk=^G");
        assert_eq!(rendered(&page, 1), "\\u{202e}evil\\u{9b}31m");
        let frame = frame(&page, " t", 0, 10, 80).unwrap();
        assert!(!frame.windows(4).any(|w| w == b"\x1b]52"), "the clipboard write reached the terminal");
        assert!(!frame.windows(3).any(|w| w == "\u{202e}".as_bytes()));
    }

    #[test]
    fn shows_anything_but_text_in_hex() {
        let page = Page::new(b"\x00\x01ABC\xff", 80);
        assert!(matches!(page.layout, Layout::Hex { per_row: 16, .. }));
        let row = rendered(&page, 0);
        assert!(row.starts_with("00000000  00 01 41 42 43 ff "), "{row}");
        assert!(row.ends_with("|..ABC.|"), "{row}");
        assert_eq!(row.len(), hex_width(16) - 10, "the last row's text lines up under the others");
        assert!(matches!(Page::new(b"\x00", 60).layout, Layout::Hex { per_row: 8, .. }));
        let full = rendered(&Page::new(&[0x80; 16], 80), 0);
        assert_eq!(full.len(), hex_width(16));
    }

    #[test]
    fn keeps_its_place_when_the_window_is_resized() {
        let text: String = (0..100).map(|n| format!("line {n} {}\n", "x".repeat(n % 50))).collect();
        let wide = Page::new(text.as_bytes(), 120);
        let offset = wide.offset(40);
        let narrow = Page::new(text.as_bytes(), 20);
        let row = narrow.row_at(offset);
        assert!(narrow.offset(row) <= offset && offset < narrow.offset(row + 1));
        assert!(rendered(&narrow, row).starts_with("line 40 "));
    }

    #[test]
    fn frames_never_outgrow_their_memory() {
        // Wide characters, escaped controls and tabs, the most bytes a column.
        let worst = "\u{4e2d}\u{1f600}\u{9b}\t\x01é".repeat(2000);
        for cols in [1, 7, 80, 200] {
            let page = Page::new(worst.as_bytes(), cols);
            for top in [0, page.rows() / 2] {
                let frame = frame(&page, &"n".repeat(300), top, 50, cols).unwrap();
                assert!(frame.len() <= frame_capacity(50, cols), "{cols} columns");
            }
        }
    }

    #[test]
    fn fits_every_row_to_the_width() {
        let text: String = (0..300).map(|n| format!("{n}\t{}\n", "word ".repeat(n % 40))).collect();
        for cols in [20, 33, 80] {
            let page = Page::new(text.as_bytes(), cols);
            for row in 0..page.rows() {
                assert!(rendered(&page, row).chars().count() <= cols, "row {row} at {cols} columns");
            }
            assert!(frame(&page, " t", 5, 24, cols).unwrap().len() <= frame_capacity(24, cols), "the frame grew");
        }
    }
}
