//! The screen encryptor runs on at a terminal. Whatever the command, it takes
//! over the window on the terminal's alternate screen, the one full-screen
//! programs like `less` use, with its name in large letters at the top. At
//! the end, Enter wipes everything it showed and the window comes back as it
//! was, with its history. Nothing shown on the alternate screen reaches the
//! window's scrollback.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};
use crate::{home, recording, term};

/// Onto the alternate screen, cleared.
const ENTER: &str = "\x1b[?1049h\x1b[H\x1b[2J";
/// The cursor shown again, the alternate screen cleared, and back to the
/// window. Clearing the alternate screen is enough, as it keeps no scrollback;
/// erasing scrollback as well (ESC [3J) could reach the window's own history
/// in some terminals.
const LEAVE: &str = "\x1b[?25h\x1b[H\x1b[2J\x1b[?1049l";

static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Set when the run should end without waiting for Enter, as after `q` on
/// the home screen.
static CLOSE_NOW: AtomicBool = AtomicBool::new(false);
/// The version under the art, and lines shown again under it when the screen
/// is drawn afresh after a key was shown.
static HEADER: Mutex<Option<Header>> = Mutex::new(None);

struct Header {
    version: String,
    notes: Vec<String>,
}

/// While it exists, the run is on its own screen. Dropping it, even while a
/// panic unwinds, wipes that screen and returns to the window.
pub struct Session(());

/// Whether a run can have its own screen: typing comes from a terminal, and
/// everything it shows goes to one that can draw it.
pub fn available() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && !term.is_empty()
        && term != "dumb"
}

/// Moves to the run's own screen and draws the art at the top, or returns
/// `None`, as in scripts, where everything is printed as usual.
pub fn start(version: String) -> Option<Session> {
    if !available() || to_terminal(ENTER).is_err() {
        return None;
    }
    ACTIVE.store(true, Ordering::SeqCst);
    *header_lock() = Some(Header { version, notes: Vec::new() });
    header();
    Some(Session(()))
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// Ends the run without asking for Enter.
pub fn close_now() {
    CLOSE_NOW.store(true, Ordering::SeqCst);
}

/// Clears the screen and draws the art at the top, followed by anything
/// remembered. Does nothing outside a session.
pub fn header() {
    if !active() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
    let text = match header_lock().as_ref() {
        Some(header) => render(&header.version, &header.notes, columns(), color),
        None => return,
    };
    let _ = to_terminal(&format!("\x1b[H\x1b[2J{text}"));
}

/// Keeps a line already shown, such as the file being encrypted, to show
/// again under the art when the screen is drawn afresh.
pub fn remember(line: String) {
    if let Some(header) = header_lock().as_mut() {
        header.notes.push(line);
    }
}

impl Session {
    /// Shows the error the run ended with, if any, and waits for Enter before
    /// the screen is wiped. A run that was interrupted, or ended with `q`,
    /// closes straight away.
    pub fn finish(self, result: &Result<()>) {
        if matches!(result, Err(Error::Interrupted)) || CLOSE_NOW.load(Ordering::SeqCst) {
            return;
        }
        if let Err(e) = result {
            eprintln!("\nerror: {e}");
        }
        let recorders = recording::scan();
        if !recorders.is_empty() {
            eprintln!();
            eprintln!("note: wiping this screen won't remove what these have recorded:");
            for recorder in &recorders {
                eprint!("{recorder}");
            }
        }
        eprint!("\nPress Enter to exit and wipe this screen: ");
        // Ctrl-C here exits too.
        let _ = term::press_enter();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = to_terminal(LEAVE);
        ACTIVE.store(false, Ordering::SeqCst);
        header_lock().take();
    }
}

fn header_lock() -> std::sync::MutexGuard<'static, Option<Header>> {
    HEADER.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The art, when the window is wide enough for it, the version, and the
/// remembered lines, each followed by a blank line.
fn render(version: &str, notes: &[String], cols: usize, color: bool) -> String {
    let mut out = String::new();
    let margin = "  ";
    let art_width = margin.len() + home::ART.iter().map(|line| line.len()).max().unwrap_or(0);
    if cols >= art_width {
        let style = if color { "\x1b[1;36m" } else { "\x1b[1m" };
        for line in home::ART {
            out.push_str(&format!("{margin}{style}{line}\x1b[0m\n"));
        }
        out.push('\n');
    }
    out.push_str(&format!("{margin}\x1b[1m{version}\x1b[0m\n\n"));
    for note in notes {
        out.push_str(note);
        out.push('\n');
    }
    if !notes.is_empty() {
        out.push('\n');
    }
    out
}

/// Columns of the window, or the classic 80 if unknown.
fn columns() -> usize {
    // SAFETY: winsize is plain data, filled in by the ioctl.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: asks the terminal on standard error for its size.
    let known = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    match known && size.ws_col > 0 {
        true => usize::from(size.ws_col),
        false => 80,
    }
}

/// Writes straight to the terminal, after anything waiting in standard output,
/// so it lands in order with what the run has printed.
fn to_terminal(text: &str) -> io::Result<()> {
    io::stdout().flush()?;
    let mut tty = OpenOptions::new().write(true).open("/dev/tty")?;
    tty.write_all(text.as_bytes())?;
    tty.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn draws_the_art_then_the_version_then_the_notes() {
        let notes = vec!["File to encrypt: report.pdf".to_string(), "Key saved as: report.pdf.key".to_string()];
        let lines = visible(&render("encryptor 9.9.9", &notes, 80, true));
        let version = lines.iter().position(|line| line.trim() == "encryptor 9.9.9").expect("the version");
        assert!(lines[..version].iter().any(|line| line.contains("___ _ __   ___")), "art above the version");
        let file = lines.iter().position(|line| line == "File to encrypt: report.pdf").expect("the first note");
        assert!(file > version);
        assert_eq!(lines[file + 1], "Key saved as: report.pdf.key");
        assert!(lines.iter().all(|line| line.chars().count() <= 80));
    }

    #[test]
    fn leaves_out_the_art_when_too_narrow_for_it() {
        let lines = visible(&render("encryptor 9.9.9", &[], 40, false));
        assert!(!lines.iter().any(|line| line.contains("___")), "{lines:?}");
        assert_eq!(lines[0].trim(), "encryptor 9.9.9");
    }

    #[test]
    fn leaves_the_window_and_its_scrollback_alone() {
        assert!(ENTER.starts_with("\x1b[?1049h"));
        assert!(LEAVE.ends_with("\x1b[?1049l"), "back to the window last");
        for text in [ENTER, LEAVE] {
            assert!(!text.contains("\x1b[3J"), "{text:?} would erase scrollback");
        }
    }
}
