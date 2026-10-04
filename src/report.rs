//! The report printed when a command succeeds, which can be saved as a text
//! file, and after which the terminal is wiped.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Result;
use crate::explain::{self, Action};
use crate::term::{self, confirm, safe};

/// Prints the report. With `ask`, it then offers to save it in the current
/// folder as `<summary>.txt`, and waits for Enter to wipe the terminal,
/// scrollback and all, so nothing the run showed stays on screen.
pub fn show(title: &str, rows: &[(&str, String)], summary: &str, ask: bool) -> Result<()> {
    let text = text(title, rows);
    print!("\n{text}");
    io::stdout().flush().map_err(|e| format!("cannot write the report: {e}"))?;
    if ask {
        // Stopping at either question just skips to the wipe: the work is done.
        let _ = offer_to_save(&text, summary).and_then(|()| term::wait_to_wipe());
        term::wipe_screen();
    }
    Ok(())
}

fn text(title: &str, rows: &[(&str, String)]) -> String {
    let rule = "-".repeat(64);
    let mut text = format!("{rule}\n  {title}\n{rule}\n");
    for (label, value) in rows {
        text.push_str(&format!("  {label:<14} {value}\n"));
    }
    text.push_str(&rule);
    text.push('\n');
    text
}

/// Asks whether to save the report, and saves it under the first free name,
/// readable only by its owner. A failure to save is said, not returned, so
/// the terminal is still wiped.
fn offer_to_save(text: &str, summary: &str) -> Result<()> {
    let name = (1..=1000)
        .map(|n| if n == 1 { format!("{summary}.txt") } else { format!("{summary}.{n}.txt") })
        .find(|name| Path::new(name).symlink_metadata().is_err())
        .unwrap_or_else(|| format!("{summary}.txt"));
    if !confirm(&format!("Save this summary as {} in the current folder?", safe(&name)))? {
        return Ok(());
    }
    let saved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&name)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()));
    match saved {
        Ok(()) => eprintln!("Summary saved as {}", safe(&name)),
        Err(e) => eprintln!("  {}", explain::file(Action::Create, Path::new(&name), &e)),
    }
    Ok(())
}

pub fn fmt_size(bytes: usize) -> String {
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = "";
    for u in ["KiB", "MiB", "GiB", "TiB"] {
        value /= 1024.0;
        unit = u;
        if value < 1024.0 {
            break;
        }
    }
    format!("{bytes} bytes ({value:.1} {unit})")
}
