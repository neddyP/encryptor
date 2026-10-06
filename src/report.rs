//! The report printed when a command succeeds, which can be saved as a text
//! file.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Result;
use crate::explain::{self, Action};
use crate::term::{confirm, safe};

/// Prints the report. With `ask`, it then offers to save it as a text file.
/// What's shown keeps the file names and paths; what's saved to disk leaves
/// them out (`secrets` are the rendered names and paths to redact, and any
/// absolute or `~/` path is stripped too), so a kept copy says what was done
/// without saying to which file. At a terminal, the run's screen is wiped when
/// it ends (see `session`).
pub fn show(title: &str, rows: &[(&str, String)], summary_base: &str, ask: bool, secrets: &[String]) -> Result<()> {
    let text = text(title, rows);
    print!("\n{text}");
    io::stdout().flush().map_err(|e| format!("cannot write the report: {e}"))?;
    if ask {
        // Stopping at the question is fine: the work is done.
        let _ = offer_to_save(&redact(&text, secrets), summary_base);
    }
    Ok(())
}

/// Removes names and paths from the report before it's saved: first each known
/// name or path, longest first so a name isn't half-removed inside a longer
/// path, then any token left that is an absolute or `~/` path, such as a
/// history file the run cleaned.
fn redact(text: &str, secrets: &[String]) -> String {
    let mut secrets: Vec<&str> = secrets.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();
    secrets.sort_by_key(|s| core::cmp::Reverse(s.len()));
    let mut out = text.to_string();
    for secret in secrets {
        out = out.replace(secret, "…");
    }
    strip_paths(&out)
}

/// Replaces every whitespace-delimited token that is an absolute or `~/` path
/// with `…`, keeping all the whitespace as it was.
fn strip_paths(text: &str) -> String {
    fn flush(token: &mut String, out: &mut String) {
        if token.len() > 1 && (token.starts_with('/') || token.starts_with("~/")) {
            out.push('…');
        } else {
            out.push_str(token);
        }
        token.clear();
    }
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for ch in text.chars() {
        if ch.is_whitespace() {
            flush(&mut token, &mut out);
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    flush(&mut token, &mut out);
    out
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
/// readable only by its owner. The name is generic (not the encrypted file's)
/// so it gives nothing away either. A failure to save is said, not returned,
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

pub fn fmt_size(bytes: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_files_over_4_gib_on_32_bit_systems_too() {
        assert_eq!(fmt_size(512), "512 bytes");
        assert_eq!(fmt_size(5 << 30), "5368709120 bytes (5.0 GiB)");
    }

    #[test]
    fn saved_copy_leaves_out_names_and_paths() {
        let rows = [
            ("Key storage", "saved to /home/you/Docs/report.pdf.key (owner read/write only)".to_string()),
            ("Input", "report.pdf  1.2 MiB".to_string()),
            ("Output", "report.pdf.enc  1.2 MiB".to_string()),
            ("Shell history", "removed 1 entry that ran this tool, from ~/.bash_history".to_string()),
        ];
        let full = text("ENCRYPTION SUCCESSFUL", &rows);
        let secrets = [
            "report.pdf".to_string(),
            "report.pdf.enc".to_string(),
            "/home/you/Docs/report.pdf.key".to_string(),
        ];
        let saved = redact(&full, &secrets);

        // On screen, everything stays; in the saved copy, no name or path does.
        assert!(full.contains("report.pdf"));
        for leak in ["report.pdf", "report.pdf.enc", "/home/you", ".key", "~/.bash_history"] {
            assert!(!saved.contains(leak), "{leak:?} is still in the saved copy:\n{saved}");
        }
        // The rest is kept: the labels, the sizes, and the surrounding words.
        assert!(saved.contains("Output"));
        assert!(saved.contains("1.2 MiB"));
        assert!(saved.contains("owner read/write only"));
        assert!(saved.contains("removed 1 entry that ran this tool, from …"));
    }

    #[test]
    fn strips_paths_but_keeps_ordinary_words_and_spacing() {
        assert_eq!(strip_paths("from ~/.zsh_history now"), "from … now");
        assert_eq!(strip_paths("to /etc/x and back"), "to … and back");
        assert_eq!(strip_paths("Input          a.b  1 KiB"), "Input          a.b  1 KiB");
        assert_eq!(strip_paths("a/b is relative"), "a/b is relative", "only leading / or ~/ is a path");
    }
}
