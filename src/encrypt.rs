//! The encrypt command: checks, key, chunked encryption, verification from
//! disk, then the original is destroyed with its thumbnails, unless
//! kept, and a report printed.

use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::cli::Options;
use crate::error::{Error, Result};
use crate::explain::{self, Action};
use crate::files::{self, PartFile};
use crate::keys::{self, KeySource, Printed, UnusedKeyFile};
use crate::meta::Metadata;
use crate::report::{self, fmt_size};
use crate::term::{confirm, safe_path};
use crate::{KEY_LEN, MAGIC, desktop, history, kdf, protect, session, stream, wipe};

pub fn command(file: Option<&str>, options: &Options) -> Result<()> {
    command_path(files::file_path("encrypt", file)?, options)
}

/// The encrypt command for one file, `input`.
pub fn command_path(input: PathBuf, options: &Options) -> Result<()> {
    let (original, output) = check(&input, options)?;
    session::remember(format!("File to encrypt: {}", safe_path(&input)));
    if let Some(new_key) = &options.new_key {
        keys::check_new_key(new_key)?;
    }
    if let Some(filesystem) = files::copy_on_write(original.file()).filter(|_| !options.keep)
        && !copy_on_write_ok(&input, filesystem, 0, options)?
    {
        return Ok(());
    }

    let mut key_file = UnusedKeyFile::default();
    let (secret, source) = keys::establish(&input, &mut key_file, options)?;
    let history = history::clean(secret.held());

    if !options.yes && !confirm("Encrypt using AES-256-GCM?")? {
        eprintln!("Cancelled; nothing was encrypted.");
        return Ok(());
    }
    let started = Instant::now();
    let sealed = seal(&input, &output, original, &secret, &mut key_file, options.keep)?;
    drop(secret);
    let elapsed = started.elapsed();
    if options.quiet {
        return Ok(());
    }

    let mut rows = vec![("Cipher", "AES-256-GCM (authenticated encryption)".to_string())];
    rows.extend(key_rows(&source));
    let tags = sealed.chunks as usize * stream::TAG_LEN;
    let overhead = sealed.header_len + sealed.meta_len + tags;
    rows.extend([
        ("File key", "derived with HKDF-SHA256 from the key and a random 256-bit salt".into()),
        (
            "Chunks",
            format!("{} of up to 64 KiB, each with its own {}-bit auth tag", sealed.chunks, stream::TAG_LEN * 8),
        ),
        ("Input", format!("{}  {}", safe_path(&input), fmt_size(sealed.len))),
        ("Output", format!("{}  {}", safe_path(&output), fmt_size(sealed.len + overhead as u64))),
        (
            "Overhead",
            format!(
                "{overhead} bytes ({} header + {} metadata + {tags} in tags)",
                sealed.header_len, sealed.meta_len
            ),
        ),
        ("Metadata", format!("stored encrypted: {}", sealed.metadata)),
        ("Integrity", "verified: re-read from disk, decrypted, SHA-256 matches original".into()),
        ("Original", sealed.original),
    ]);
    if let Some(thumbnails) = sealed.thumbnails {
        rows.push(("Thumbnails", thumbnails_status(thumbnails)));
    }
    rows.extend([
        ("Key and data", protect::memory_status().into()),
        ("Shell history", history),
        ("Time", format!("{elapsed:.2?}")),
    ]);
    let ask = io::stdin().is_terminal() && !options.yes;
    report::show("ENCRYPTION SUCCESSFUL", &rows, "encryption-summary", ask)
}

/// Checks `input` can be encrypted to `<input>.enc`, before any key is made,
/// since problems found now save asking for a key that can't be used. Unless
/// it's to be kept, the original is opened to be overwritten too, which fails
/// now if that couldn't be done later. Returns it open, with the output's path.
pub fn check(input: &Path, options: &Options) -> Result<(wipe::Original, PathBuf)> {
    files::input_len("encrypt", input)?;
    let output = files::encrypted_path(input);
    if output.exists() {
        return Err(Error::File(explain::output_exists(&output)));
    }
    let original = wipe::Original::open(input, !options.keep)?;
    files::check_writable(&output)?;
    Ok((original, output))
}

/// Warns that `input`, and `others` more files, are on a copy-on-write
/// filesystem, where overwriting can't reach the old contents, and says
/// whether to go ahead. Only asked of someone at the keyboard: it's asked on
/// some disks and not others, so answers piped in would land on the wrong
/// questions. Scripts are warned, and carry on as with --yes.
pub fn copy_on_write_ok(input: &Path, filesystem: &str, others: usize, options: &Options) -> Result<bool> {
    eprintln!("{}", explain::copy_on_write(input, filesystem));
    if others > 0 {
        eprintln!("The same goes for {others} more of the files.");
    }
    if files::filevault_off() == Some(true) {
        eprintln!("{}", explain::FILEVAULT_OFF);
    }
    if !options.yes && io::stdin().is_terminal() && !confirm("Encrypt anyway?")? {
        eprintln!("Cancelled; nothing was encrypted.");
        return Ok(false);
    }
    Ok(true)
}

/// What encrypting one file did, for the report.
pub struct Sealed {
    pub len: u64,
    pub header_len: usize,
    pub meta_len: usize,
    pub chunks: u64,
    /// The metadata stored, described.
    pub metadata: String,
    /// What became of the original.
    pub original: String,
    /// Thumbnails of the original removed, where a desktop keeps them.
    pub thumbnails: Option<usize>,
}

/// Encrypts `input`, open as `original`, to `output` with `secret`, proves the
/// file on disk decrypts back to it, then destroys the original unless it's to
/// be kept. `key_file` is kept from the moment the encrypted file is verified,
/// as from then on it's needed.
pub fn seal(
    input: &Path,
    output: &Path,
    mut original: wipe::Original,
    secret: &keys::Secret,
    key_file: &mut UnusedKeyFile,
    keep: bool,
) -> Result<Sealed> {
    // A passphrase is made into a key with the new header's salt.
    let header = stream::header(secret.kdf()).map_err(|e| explain::stream_failure(e, input, output, None))?;
    let key = secret.key_for(&header)?;

    let read_error = |e| Error::File(explain::file(Action::Read, input, &e));
    let before = original.file().metadata().map_err(read_error)?;
    let len = before.len();
    // Captured before reading, which can update the access time.
    let metadata = Metadata::capture(original.file()).map_err(read_error)?;
    let meta_len = metadata.encoded_len();
    let mut encoded = files::secret_buffer(meta_len as u64)?;
    metadata.encode(&mut encoded);

    // A chunk at a time, so the file can be any size.
    let mut out = PartFile::create(output, false)?;
    let mut progress = crate::progress::Progress::new("Encrypting", len);
    let sealed = stream::encrypt(
        &key,
        &header,
        &encoded,
        &mut original.reader().map_err(read_error)?,
        len,
        &mut out,
        &mut |done| progress.update(done),
    )
    .map_err(|e| explain::stream_failure(e, input, output, None))?;
    drop(progress);
    out.finish()?;
    drop(encoded);

    // Prove the file on disk decrypts back to exactly what was read before the
    // original is touched.
    if let Err(e) = verify(&key, output, len, &sealed.hash) {
        let _ = wipe::shred(output);
        return Err(match e {
            Error::Interrupted => e,
            e => Error::File(format!(
                "{e}\nThe encrypted file didn't read back from disk as it was written, so it was \
                 removed and the original left untouched.\n{}",
                explain::DISK_TROUBLE
            )),
        });
    }
    drop(key);

    // Anything written to the original while it was read would be lost with
    // it, and the encrypted copy wouldn't match it either way.
    let after = original.file().metadata().map_err(read_error)?;
    if after.len() != len || after.modified().ok() != before.modified().ok() {
        let _ = wipe::shred(output);
        return Err(Error::File(explain::changed_while_reading(input)));
    }

    // Last chance to back out: past this point the original is destroyed.
    if protect::stop_requested() {
        let _ = wipe::shred(output);
        return Err(Error::Interrupted);
    }
    key_file.keep();
    let (original_status, thumbnails) = match keep {
        true => ("kept, as asked with --keep".into(), None),
        false => match original.destroy(input) {
            Ok(status) => (status, desktop::remove_thumbnails(input)),
            Err(warning) => (warning, None),
        },
    };
    Ok(Sealed {
        len,
        header_len: header.len(),
        meta_len,
        chunks: sealed.chunks,
        metadata: metadata.summary(),
        original: original_status,
        thumbnails,
    })
}

/// The report's line on thumbnails removed.
pub fn thumbnails_status(removed: usize) -> String {
    match removed {
        0 => "none found".into(),
        n => format!("removed {n}"),
    }
}

/// The report's rows on the key and where it's kept.
pub fn key_rows(source: &KeySource) -> [(&'static str, String); 2] {
    match source {
        KeySource::Generated { saved_to, printed } => [
            ("Key", "256-bit, generated by the OS CSPRNG".into()),
            ("Key storage", key_storage(saved_to.as_deref(), printed)),
        ],
        KeySource::FromFile { path } => [
            ("Key", format!("256-bit, from {}", safe_path(path))),
            ("Key storage", "your key file; not changed by this tool".into()),
        ],
        KeySource::Entered => [
            ("Key", "256-bit, entered by you".into()),
            ("Key storage", "not stored by this tool".into()),
        ],
        KeySource::Passphrase => [
            ("Key", format!("256-bit, from your passphrase with {}", kdf::DEFAULT.summary())),
            ("Key storage", "your passphrase; not stored by this tool".into()),
        ],
    }
}

/// Where a generated key went, for the report.
fn key_storage(saved_to: Option<&Path>, printed: &Printed) -> String {
    match (saved_to, printed) {
        (Some(path), Printed::No) => format!("saved to {} (owner read/write only)", safe_path(path)),
        (Some(path), Printed::Erased) => {
            format!("saved to {} (owner read/write only); also shown once on screen", safe_path(path))
        }
        (Some(path), Printed::Captured(by)) => format!(
            "saved to {} (owner read/write only); also shown on screen and captured by {by}: anyone \
             with that copy can decrypt the file",
            safe_path(path)
        ),
        (None, Printed::Captured(by)) => {
            format!("shown on screen and captured by {by}: anyone with that copy can decrypt the file; not saved")
        }
        (None, _) => "shown once on screen, then erased; not saved".into(),
    }
}

/// Checks that the encrypted file decrypts back to the original contents, and
/// that its metadata reads back too, reading it a chunk at a time from the
/// disk rather than from memory.
pub fn verify(key: &[u8; KEY_LEN], path: &Path, len: u64, hash: &[u8; 32]) -> Result<()> {
    let read_error = |e| Error::File(explain::file(Action::Read, path, &e));
    let mut file = files::open_uncached(path).map_err(read_error)?;
    // The version, then the rest of the header, which is longer for a
    // passphrase.
    let mut header = vec![0u8; MAGIC.len() + 1];
    file.read_exact(&mut header).map_err(read_error)?;
    header.resize(stream::header_len(header[MAGIC.len()]), 0);
    file.read_exact(&mut header[MAGIC.len() + 1..]).map_err(read_error)?;
    let body_len = file.metadata().map_err(read_error)?.len().saturating_sub(header.len() as u64);
    let mut progress = crate::progress::Progress::new("Verifying", body_len);
    let opened = stream::decrypt(key, &header, &mut file, body_len, &mut std::io::sink(), &mut |done| {
        progress.update(done)
    })
    .map_err(|e| match e {
        stream::Error::Auth { chunk, .. } => {
            format!("verification failed: chunk {chunk} of the encrypted file didn't decrypt").into()
        }
        e => match explain::stream_failure(e, path, path, None) {
            Error::Interrupted => Error::Interrupted,
            e => format!("verification failed: {e}").into(),
        },
    })?;
    if opened.len != len || *opened.hash != *hash {
        return Err("verification failed: the encrypted file doesn't decrypt to the original".into());
    }
    Ok(())
}
