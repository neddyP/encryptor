//! The decrypt command: checks, key, decryption of any format version,
//! verification from disk, metadata restored, then a report printed.

use std::io::{self, IsTerminal, Read, Write};
use std::time::Instant;

use crate::cli::Options;
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::{self, PartFile, Replaced};
use crate::keys;
use crate::report::{self, fmt_size};
use crate::term::{self, confirm, safe, safe_path};
use crate::{MAGIC, VERSION, history, legacy, protect, stream, wipe};

pub fn command(file: Option<&str>, options: &Options) -> Result<()> {
    let input = files::file_path("decrypt", file)?;
    let input_len = files::input_len("decrypt", &input)?;

    // Reject files this tool didn't produce before asking for the key, saying
    // what they are instead where that can be told. The file stays open, and
    // a version 3 file is decrypted from this same handle.
    let read_error = |e| Error::File(explain::file(Action::Read, &input, &e));
    let mut source = files::open_no_follow(&input).map_err(read_error)?;
    let mut start = Vec::with_capacity(stream::HEADER_LEN);
    (&mut source).take(stream::HEADER_LEN as u64).read_to_end(&mut start).map_err(read_error)?;
    if !start.starts_with(MAGIC) {
        return Err(Error::File(explain::not_encrypted(&input, &start)));
    }
    let min_len = match start.get(MAGIC.len()) {
        Some(&stream::VERSION) => stream::MIN_LEN,
        _ => legacy::MIN_LEN,
    };
    if input_len < min_len {
        return Err(Error::KeyOrData(explain::too_short(&input, input_len, min_len)));
    }
    let version = check_header(&start)?;

    let output = options.output.clone().unwrap_or_else(|| files::decrypted_path(&input));
    if files::same_file(&input, &output) {
        return Err(Error::Usage(format!(
            "{} is the encrypted file itself; choose another name with --output",
            safe_path(&output)
        )));
    }
    files::check_writable(&output)?;
    // Replacing a file is never agreed to through a pipe: a script says so
    // with --overwrite, and otherwise finds out before giving a key.
    let replace = output.exists();
    let interactive = io::stdin().is_terminal();
    if replace && !options.overwrite && !interactive {
        return Err(Error::Usage(explain::needs_overwrite(&output)));
    }

    let (key, key_file) = match &options.key_file {
        Some(path) => (keys::read_key_file(path)?, Some(path.clone())),
        None => {
            let plain_name = output.file_name().unwrap_or_default().to_string_lossy();
            let give_up = format!(
                "no valid key after 3 attempts.\nRun decrypt again with this file's key: the 64 characters \
                 printed when it was encrypted, or its key file, usually {}.key.",
                safe(&plain_name)
            );
            keys::prompt(false, &give_up)?
        }
    };
    let history = history::clean(Some(&key));

    if !options.yes && !confirm("Decrypt using AES-256-GCM?")? {
        eprintln!("Cancelled; nothing was decrypted.");
        return Ok(());
    }
    if replace && !options.overwrite && !confirm(&format!("{} already exists. Overwrite it?", safe_path(&output)))? {
        eprintln!("Cancelled; nothing was written.");
        return Ok(());
    }

    let started = Instant::now();
    let mut out = PartFile::create(&output, replace)?;
    let (metadata, plain_len, plain_hash) = if version == stream::VERSION {
        let header = start[..].try_into().expect("a version 3 file this long has a whole header");
        let body_len = source.metadata().map_err(read_error)?.len().saturating_sub(stream::HEADER_LEN as u64);
        let mut progress = term::Progress::new("Decrypting", body_len);
        let opened =
            stream::decrypt(&key, &header, &mut source, body_len, &mut out, &mut |done| progress.update(done))
                .map_err(|e| explain::stream_failure(e, &input, &output, key_file.as_deref()))?;
        (Some(opened.metadata), opened.len, opened.hash)
    } else {
        // Versions 1 and 2 were encrypted whole, so they are decrypted whole.
        let (metadata, plain) = legacy::decrypt(&key, files::read_file(&input)?).map_err(|e| match e {
            Error::AuthFailed => Error::KeyOrData(explain::wrong_key(&input, key_file.as_deref())),
            Error::Message(e) => Error::KeyOrData(e),
            e => e,
        })?;
        out.write_all(&plain).map_err(|e| Error::File(explain::file(Action::Write, &output, &e)))?;
        (metadata, plain.len() as u64, files::sha256(&plain))
    };
    drop(key);
    let replaced = out.finish()?;

    if *files::sha256_file(&output)? != *plain_hash {
        let _ = wipe::shred(&output);
        return Err(Error::File(format!(
            "{} didn't read back from disk as it was written, so it was removed. The encrypted \
             file is untouched.\n{}",
            safe_path(&output),
            explain::DISK_TROUBLE
        )));
    }
    if protect::stop_requested() {
        let _ = wipe::shred(&output);
        return Err(Error::Interrupted);
    }
    // Only now, since the original permissions may not let the file be read
    // back or shredded.
    let metadata_status = match metadata {
        Some(metadata) => match files::open_no_follow(&output) {
            Ok(file) => metadata.restore(&file),
            Err(e) => format!("not restored: {}", explain::cause(Action::Read, &output, &e)),
        },
        None => "none stored (encrypted by a version before 2.0)".into(),
    };
    let elapsed = started.elapsed();
    if options.quiet {
        return Ok(());
    }

    let replaced = match replaced {
        Replaced::Nothing => "",
        Replaced::Shredded => "; the file it replaced was overwritten with zeros",
        Replaced::Unlinked => "; the file it replaced was deleted but not overwritten, as other names lead to it",
    };
    let name = output.file_name().unwrap_or_default().to_string_lossy();
    report::show(
        "DECRYPTION SUCCESSFUL",
        &[
            ("Cipher", "AES-256-GCM (authenticated encryption)".into()),
            ("Key", "256-bit".into()),
            ("Auth tag", "128-bit, valid: file is authentic and uncorrupted".into()),
            ("Input", format!("{}  {} (kept)", safe_path(&input), fmt_size(input_len as usize))),
            ("Output", format!("{}  {}{replaced}", safe_path(&output), fmt_size(plain_len as usize))),
            ("Integrity", "verified: re-read from disk, SHA-256 matches decrypted data".into()),
            ("Metadata", metadata_status),
            ("Key and data", protect::memory_status().into()),
            ("Shell history", history),
            ("Time", format!("{elapsed:.2?}")),
        ],
        &format!("{name}.decryption-summary"),
        interactive && !options.yes,
    )
}

/// Checks the magic bytes and returns the format version, if it's one this
/// version reads.
fn check_header(bytes: &[u8]) -> Result<u8> {
    if bytes.len() <= MAGIC.len() || !bytes.starts_with(MAGIC) {
        return Err(Error::File("not a file encrypted by this tool (missing AGCM header)".into()));
    }
    match bytes[MAGIC.len()] {
        v @ 1..=VERSION => Ok(v),
        v => Err(Error::File(explain::unsupported_version(v))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(result: Result<u8>) -> String {
        match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn reads_every_version_up_to_its_own() {
        for v in 1..=VERSION {
            assert!(matches!(check_header(&[b'A', b'G', b'C', b'M', v]), Ok(found) if found == v));
        }
        assert!(message(check_header(&[b'A', b'G', b'C', b'M', VERSION + 1])).contains("made by a newer version"));
        assert!(message(check_header(b"AGCM")).contains("missing AGCM header"));
    }
}
