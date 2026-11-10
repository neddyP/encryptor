//! The report printed when a command succeeds, which can be saved as a text
//! file.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Result;
use crate::explain::{self, Action};
use crate::term::{confirm, safe, short_size};

/// Prints the report. With `ask`, it then offers to save it as a text file.
/// At a terminal, the run's screen is wiped when it ends (see `session`).
pub fn show(title: &str, rows: &[(&str, String)], summary_base: &str, ask: bool) -> Result<()> {
    let text = text(title, rows);
    print!("\n{text}");
    io::stdout().flush().map_err(|e| format!("cannot write the report: {e}"))?;
    if ask {
        // Stopping at the question is fine: the work is done.
        let _ = offer_to_save(&text, summary_base);
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
/// readable only by its owner. A failure to save is said, not returned,
/// since the encrypting or decrypting it reports on has succeeded.
fn offer_to_save(text: &str, summary_base: &str) -> Result<()> {
    let name = (1..=1000)
        .map(|n| if n == 1 { format!("{summary_base}.txt") } else { format!("{summary_base}.{n}.txt") })
        .find(|name| Path::new(name).symlink_metadata().is_err())
        .unwrap_or_else(|| format!("{summary_base}.txt"));
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

/// The exact size, and in KiB, MiB and so on once it's that large.
pub fn fmt_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} bytes"),
        _ => format!("{bytes} bytes ({})", short_size(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_files_over_4_gib_on_32_bit_systems_too() {
        assert_eq!(fmt_size(512), "512 bytes");
        assert_eq!(fmt_size(5 << 30), "5368709120 bytes (5.0 GiB)");
    }
}
