//! Progress bars on standard error, at a terminal only: one for each long
//! step with a large file, and for a batch of files, one line for the whole
//! batch, redrawn as it goes, with each step's progress folded into it.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::term::{safe_path, short_size};

/// Files this large get a bar of their own for each step; smaller ones are
/// done before one would be worth drawing.
const LARGE: u64 = 64 << 20;
/// Bars are redrawn at most this often.
const EVERY: Duration = Duration::from_millis(250);
/// Characters inside a bar.
const WIDTH: usize = 24;
/// The steps whose bytes move a batch's bar, as each reads its file through
/// once. Verifying and shredding show their own percentage beside it.
const MAIN_STEPS: [&str; 2] = ["Encrypting", "Decrypting"];

/// A bar for one long step with one file, such as encrypting it, shown only
/// at a terminal and for large files, and cleared when dropped. During a
/// batch it's shown on the batch's line instead.
pub struct Progress {
    label: &'static str,
    total: u64,
    shown: bool,
    in_batch: bool,
    last: Instant,
}

impl Progress {
    pub fn new(label: &'static str, total: u64) -> Self {
        let in_batch = batch_active();
        let shown = !in_batch && total >= LARGE && io::stderr().is_terminal();
        Self { label, total, shown, in_batch, last: Instant::now() }
    }

    /// Whether it has a line of its own.
    pub fn shown(&self) -> bool {
        self.shown
    }

    /// Records that `done` bytes of the total are done.
    pub fn update(&mut self, done: u64) {
        if self.in_batch {
            change_batch(false, |batch| batch.step = Some((self.label, done, self.total)));
            return;
        }
        if !self.shown || self.last.elapsed() < EVERY {
            return;
        }
        self.last = Instant::now();
        draw(&format!(
            "{} {} {:>3}% of {}",
            self.label,
            bar(fraction(done, self.total)),
            percent(done, self.total),
            short_size(self.total)
        ));
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.shown {
            clear();
        }
        if self.in_batch {
            change_batch(false, |batch| batch.step = None);
        }
    }
}

/// The overall progress of a batch of `count` files, `total` bytes in all,
/// drawn on one line at a terminal until it's dropped. Without a terminal it
/// does nothing.
pub struct Overall {
    active: bool,
}

impl Overall {
    pub fn start(count: usize, total: u64) -> Self {
        let active = io::stderr().is_terminal();
        if active && let Ok(mut batch) = BATCH.lock() {
            *batch = Some(Batch { count, total, files: 0, bytes: 0, name: String::new(), step: None, paused: false });
        }
        Self { active }
    }

    /// Whether the line is drawn, at a terminal.
    pub fn active(&self) -> bool {
        self.active
    }

    /// The file being worked on now.
    pub fn next(&self, file: &Path) {
        change_batch(true, |batch| {
            batch.name = safe_path(file);
            batch.step = None;
        });
    }

    /// The file being worked on is done, and was `len` bytes.
    pub fn done(&self, len: u64) {
        change_batch(true, |batch| {
            batch.files += 1;
            batch.bytes += len;
            batch.step = None;
        });
    }

    /// Takes the line away while something else is shown, such as questions.
    pub fn pause(&self) {
        change_batch(false, |batch| {
            if !batch.paused {
                clear();
            }
            batch.paused = true;
        });
    }

    /// Draws the line again after `pause`.
    pub fn resume(&self) {
        change_batch(true, |batch| batch.paused = false);
    }
}

impl Drop for Overall {
    fn drop(&mut self) {
        if let Ok(mut batch) = BATCH.lock()
            && batch.take().is_some_and(|batch| !batch.paused)
        {
            clear();
        }
    }
}

/// A batch's progress, while one is drawn.
struct Batch {
    count: usize,
    total: u64,
    /// Files done, and their bytes.
    files: usize,
    bytes: u64,
    /// The file being worked on, made safe to print.
    name: String,
    /// The step under way with it: its label, and bytes done of how many.
    step: Option<(&'static str, u64, u64)>,
    paused: bool,
}

static BATCH: Mutex<Option<Batch>> = Mutex::new(None);
static LAST_DRAWN: Mutex<Option<Instant>> = Mutex::new(None);

fn batch_active() -> bool {
    BATCH.lock().is_ok_and(|batch| batch.is_some())
}

/// Changes the batch's progress, if one is drawn, then draws it: straight
/// away if `now`, otherwise if it hasn't been for a moment.
fn change_batch(now: bool, change: impl FnOnce(&mut Batch)) {
    let Ok(mut batch) = BATCH.lock() else { return };
    let Some(batch) = batch.as_mut() else { return };
    change(batch);
    if batch.paused {
        return;
    }
    if let Ok(mut last) = LAST_DRAWN.lock() {
        if !now && last.is_some_and(|last| last.elapsed() < EVERY) {
            return;
        }
        *last = Some(Instant::now());
    }
    draw(&batch.line());
}

impl Batch {
    /// Such as `[████████░░░░] 41%  3 of 10 files, 49.2 MiB of 120.0 MiB  Verifying 60%  docs/b.pdf`.
    fn line(&self) -> String {
        let reading = match self.step {
            Some((label, done, _)) if MAIN_STEPS.contains(&label) => done,
            _ => 0,
        };
        let done = (self.bytes + reading).min(self.total);
        let part = match self.total {
            0 => fraction(self.files as u64, self.count as u64),
            total => fraction(done, total),
        };
        let mut line = format!("{} {:>3}%  {} of {} files", bar(part), (part * 100.0) as u64, self.files, self.count);
        if self.total > 0 {
            line.push_str(&format!(", {} of {}", short_size(done), short_size(self.total)));
        }
        if let Some((label, done, total)) = self.step
            && !MAIN_STEPS.contains(&label)
        {
            line.push_str(&format!("  {label} {}%", percent(done, total)));
        }
        if !self.name.is_empty() {
            line.push_str("  ");
            line.push_str(&self.name);
        }
        line
    }
}

/// `done` of `total`, from 0 to 1.
fn fraction(done: u64, total: u64) -> f64 {
    if total == 0 { 1.0 } else { (done as f64 / total as f64).clamp(0.0, 1.0) }
}

fn percent(done: u64, total: u64) -> u64 {
    (fraction(done, total) * 100.0) as u64
}

/// A bar filled to `part`, in block characters where the terminal can show
/// them and in ASCII where it can't.
fn bar(part: f64) -> String {
    static UTF8: OnceLock<bool> = OnceLock::new();
    let (full, empty) = match *UTF8.get_or_init(|| crate::art::Look::detect().utf8) {
        true => ('█', '░'),
        false => ('#', '-'),
    };
    let filled = ((part * WIDTH as f64).round() as usize).min(WIDTH);
    let mut bar = String::with_capacity(WIDTH * 3 + 2);
    bar.push('[');
    bar.extend(std::iter::repeat_n(full, filled));
    bar.extend(std::iter::repeat_n(empty, WIDTH - filled));
    bar.push(']');
    bar
}

/// Draws `line` over the current one, cut to the terminal's width so it
/// never wraps, which would leave copies of it behind.
fn draw(line: &str) {
    let cols = crate::term::size(libc::STDERR_FILENO).map_or(80, |(_, cols)| cols);
    let line: String = line.chars().take(cols.saturating_sub(1)).collect();
    let mut stderr = io::stderr();
    let _ = write!(stderr, "\r{line}\x1b[K");
    let _ = stderr.flush();
}

fn clear() {
    let mut stderr = io::stderr();
    let _ = write!(stderr, "\r\x1b[K");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_the_bar_in_proportion() {
        let ascii = |part: f64| bar(part).replace('█', "#").replace('░', "-");
        assert_eq!(ascii(0.0), format!("[{}]", "-".repeat(WIDTH)));
        assert_eq!(ascii(0.5), format!("[{}{}]", "#".repeat(WIDTH / 2), "-".repeat(WIDTH / 2)));
        assert_eq!(ascii(1.0), format!("[{}]", "#".repeat(WIDTH)));
        assert_eq!((percent(1, 3), percent(5, 0), fraction(9, 4)), (33, 100, 1.0));
    }

    #[test]
    fn counts_the_file_being_read_into_the_batch() {
        let mut batch =
            Batch { count: 4, total: 400, files: 1, bytes: 100, name: "b.pdf".into(), step: None, paused: false };
        assert!(batch.line().contains(" 25%  1 of 4 files, 100.0 bytes of 400.0 bytes  b.pdf"), "{}", batch.line());
        batch.step = Some(("Encrypting", 100, 100));
        assert!(batch.line().contains(" 50%  1 of 4 files"), "{}", batch.line());
        batch.step = Some(("Verifying", 30, 100));
        assert!(batch.line().contains(" 25%  1 of 4 files, 100.0 bytes of 400.0 bytes  Verifying 30%  b.pdf"));
    }
}
