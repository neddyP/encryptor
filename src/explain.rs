//! Error messages that say what went wrong and how to put it right. They name
//! the user's own files, escaped so they're safe to print, and the commands
//! they suggest are quoted so they can be pasted as they are.

use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::report::fmt_size;
use crate::stream;
use crate::term::{safe, safe_path};

pub const AUTH_FAILED: &str =
    "authentication failed: wrong key, or the file is corrupted or has been tampered with.";

/// What was being done with a file when something went wrong.
#[derive(Clone, Copy, PartialEq)]
pub enum Action {
    Read,
    Create,
    Write,
    Delete,
}

/// A failed file operation: what went wrong, and what to do about it.
pub fn file(action: Action, path: &Path, e: &io::Error) -> String {
    let verb = match action {
        Action::Read => "read",
        Action::Create => "create",
        Action::Write => "write",
        Action::Delete => "delete",
    };
    let (why, fix) = why_and_fix(action, path, e);
    join(format!("cannot {verb} {}: {why}.", safe_path(path)), &fix)
}

/// Just what went wrong, to fit in a sentence of its own.
pub fn cause(action: Action, path: &Path, e: &io::Error) -> String {
    why_and_fix(action, path, e).0
}

fn why_and_fix(action: Action, path: &Path, e: &io::Error) -> (String, String) {
    let folder = folder(path);
    let in_folder = folder_name(folder);
    let (why, fix) = match e.raw_os_error().unwrap_or(0) {
        libc::ENOENT if action == Action::Read => ("it doesn't exist".into(), look_here()),
        libc::ENOENT => (
            format!("{in_folder} doesn't exist"),
            "Check the path, and that the folder hasn't been moved or deleted.".into(),
        ),
        libc::EACCES | libc::EPERM if action == Action::Read => (
            "you don't have permission to read it".into(),
            format!(
                "`ls -l {}` shows who owns it and who may read it. If it isn't yours, ask its owner for access.",
                quote_path(path)
            ),
        ),
        libc::EACCES | libc::EPERM => (
            format!("you don't have permission to change files in {in_folder}"),
            "Copy the file to a folder you own, such as your home folder, and run the command there.".into(),
        ),
        libc::ENOSPC => (
            "the disk is full".into(),
            format!("Free up some space and try again. `df -h {}` shows how much is free.", quote_path(folder)),
        ),
        libc::EDQUOT => (
            "you've used all of your disk quota".into(),
            "Delete files you no longer need, or ask your administrator for more space, then try again.".into(),
        ),
        libc::EROFS => (
            format!("{in_folder} is on a read-only disk"),
            "Copy the file to a writable disk, such as your home folder, and run the command there.".into(),
        ),
        libc::EFBIG => (
            "the file is too big for this disk's format".into(),
            "Disks formatted as FAT32, common on USB sticks, can't hold files of 4 GiB or more. \
             Use a disk formatted as exFAT, NTFS, ext4 or APFS."
                .into(),
        ),
        libc::ENAMETOOLONG => (
            "the name is too long for this disk".into(),
            "Rename the file to something shorter and try again.".into(),
        ),
        libc::ENOTDIR => ("part of the path is a file, not a folder".into(), "Check the path.".into()),
        libc::EIO => (
            "the disk reported an error".into(),
            "It may be failing or have been unplugged. Check it's connected, and copy anything important off it."
                .into(),
        ),
        libc::ELOOP => (
            "it was replaced by a symbolic link part way through, so it was left alone".into(),
            "Make sure nothing else is changing files in that folder, then try again.".into(),
        ),
        _ => (e.to_string(), String::new()),
    };
    (why, fix)
}

/// A file to encrypt or decrypt that couldn't be looked at.
pub fn missing(command: &str, path: &Path, e: &io::Error) -> String {
    if e.kind() != io::ErrorKind::NotFound {
        return file(Action::Read, path, e);
    }
    let problem = format!("{} doesn't exist.", safe_path(path));
    let encrypted = crate::files::encrypted_path(path);
    if encrypted.is_file() {
        return match command {
            "decrypt" => format!("{problem}\nDid you mean the encrypted file?\n  decrypt {}", quote_path(&encrypted)),
            _ => format!(
                "{problem}\nIt may be encrypted already, as {} exists. To decrypt it:\n  decrypt {}",
                safe_path(&encrypted),
                quote_path(&encrypted)
            ),
        };
    }
    if let Some(similar) = same_name_but_case(path) {
        return format!(
            "{problem}\nDid you mean {}? Capital letters matter in names.\n  {command} {}",
            safe_path(&similar),
            quote_path(&similar)
        );
    }
    join(problem, &look_here())
}

/// A symbolic link given as the file to encrypt or decrypt.
pub fn symlink(command: &str, path: &Path) -> String {
    match fs::canonicalize(path) {
        Ok(target) => format!(
            "{} is a symbolic link to {}.\nFor safety, {command} only works on the file itself, not links to it:\n  {command} {}",
            safe_path(path),
            safe_path(&target),
            quote_path(&target)
        ),
        Err(_) => {
            let target = fs::read_link(path).map_or_else(|_| "somewhere".into(), |t| safe_path(&t));
            format!(
                "{} is a symbolic link to {target}, which doesn't exist.\nCheck where the file it pointed to has gone.",
                safe_path(path)
            )
        }
    }
}

/// Something that is neither a regular file nor a folder.
pub fn special(path: &Path, kind: fs::FileType) -> String {
    let shown = safe_path(path);
    if kind.is_block_device() || kind.is_char_device() {
        return format!(
            "{shown} is a device, not a file.\nTo encrypt a whole disk, use full-disk encryption instead: LUKS on Linux, FileVault on macOS."
        );
    }
    let what = if kind.is_fifo() { "a named pipe" } else if kind.is_socket() { "a socket" } else { "a special file" };
    format!("{shown} is {what}, not a regular file.\nSave what it holds to an ordinary file first, then use that.")
}

/// Explains that only one file can be encrypted at a time, with the commands
/// to zip `paths` (a folder, or several files) into one file and encrypt it.
pub fn zip_instead(paths: &[String]) -> String {
    let (problem, archive, zip) = match paths {
        [folder] => {
            let name = Path::new(folder).file_name().map(|n| n.to_string_lossy().into_owned());
            let archive = format!("{}.zip", name.as_deref().unwrap_or("folder"));
            let zip = format!("  Zip the folder:    zip -r {} {}", quote(&archive), quote(folder));
            (format!("{} is a folder.", safe(folder)), archive, zip)
        }
        _ => {
            let files = paths.iter().map(|p| quote(p)).collect::<Vec<_>>().join(" ");
            let files = if files.len() <= 60 { files } else { "FILE1 FILE2 ...".into() };
            let zip = format!(
                "  Zip the files:     zip -r files.zip {files}\n  \
                   Zip a folder:      zip -r folder.zip FOLDER"
            );
            (format!("encrypt was given {} files.", paths.len()), "files.zip".into(), zip)
        }
    };
    format!(
        "{problem}\n\
         encrypt can't encrypt folders or multiple files, only one file at a time.\n\
         Zip them into a single file, then encrypt that:\n\n\
         {zip}\n  \
         Encrypt the zip:   encrypt {}\n\n\
         encrypt deletes the zip once it's encrypted, but not the originals: delete\n\
         them yourself once you've checked the encrypted file.",
        quote(&archive)
    )
}

/// A folder given to decrypt.
pub fn decrypt_folder(path: &Path) -> String {
    let dir = path.to_string_lossy();
    let dir = match dir.trim_end_matches('/') {
        "" => "/",
        trimmed => trimmed,
    };
    format!(
        "{} is a folder.\ndecrypt works on one file at a time. To decrypt every .enc file in it, \
         asking for each one's key in turn:\n  for f in {}/*.enc; do decrypt \"$f\"; done",
        safe_path(path),
        quote(dir)
    )
}

/// More than one file given to decrypt.
pub fn decrypt_one_at_a_time(paths: &[String]) -> String {
    let files = paths.iter().map(|p| quote(p)).collect::<Vec<_>>().join(" ");
    let files = if files.len() <= 50 { files } else { "*.enc".into() };
    format!(
        "decrypt was given {} files.\ndecrypt works on one file at a time. To decrypt several, \
         asking for each one's key in turn:\n  for f in {files}; do decrypt \"$f\"; done",
        paths.len()
    )
}

/// A first argument that isn't a command.
pub fn unknown_command(arg: &str, usage: &str) -> String {
    let path = Path::new(arg);
    if path.is_file() {
        let command = if path.extension().is_some_and(|ext| ext == "enc") { "decrypt" } else { "encrypt" };
        return format!("'{}' is a file, not a command. To {command} it:\n  {command} {}", safe(arg), quote(arg));
    }
    if arg.starts_with('-') {
        return format!("unknown option '{}'. These are the options:\n\n{usage}", safe(arg));
    }
    format!("unknown command '{}'. The commands are encrypt and decrypt.\n\n{usage}", safe(arg))
}

pub fn no_file_given(command: &str) -> String {
    let example = if command == "decrypt" { "report.pdf.enc" } else { "report.pdf" };
    format!(
        "no file given.\nType the file's path, or drag the file into this window. \
         You can also give it on the command line, for example:\n  {command} {example}"
    )
}

/// The encrypted file to be written already exists.
pub fn output_exists(output: &Path) -> String {
    format!(
        "{} already exists, perhaps from an earlier encryption, and won't be overwritten.\n\
         If you don't need it any more, delete it. Otherwise rename it, then run encrypt again:\n  mv {} {}",
        safe_path(output),
        quote_path(output),
        quote_path(&output.with_extension("old.enc"))
    )
}

pub fn no_memory(len: u64) -> String {
    format!(
        "there isn't enough free memory: the file needs {} of RAM.\n\
         Close other programs and try again, or use a computer with more memory.",
        fmt_size(len as usize)
    )
}

pub const DISK_TROUBLE: &str = "This usually means a failing or full disk, a loose USB connection, or faulty \
                                memory. Try again; if it fails again, try another disk.";

pub fn no_working_folder(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        "the current folder no longer exists: it was deleted or moved while you were in it.\n\
         Run `cd` to go to your home folder, or cd to another folder, and try again."
            .into()
    } else {
        format!("cannot find the current folder: {e}")
    }
}

/// A file given to decrypt that doesn't start like one this tool encrypted.
/// `start` holds its first bytes.
pub fn not_encrypted(path: &Path, start: &[u8]) -> String {
    let shown = safe_path(path);
    if start.is_empty() {
        return format!("{shown} is empty, so there's nothing to decrypt.");
    }
    if path.extension().is_some_and(|ext| ext == "key") {
        let encrypted = path.with_extension("enc");
        return format!(
            "{shown} is a key file, not an encrypted file.\nDecrypt the encrypted file, and give {shown} \
             when asked for the key:\n  decrypt {}",
            quote_path(&encrypted)
        );
    }
    let tool = |tool: &str, how: String| {
        format!("{shown} was encrypted with {tool}, not with this tool.\nDecrypt it with {tool}: {how}")
    };
    if start.starts_with(b"Salted__") {
        return tool("OpenSSL", "openssl enc -d, using the cipher and password it was encrypted with.".into());
    }
    if start.starts_with(b"age-encryption.o") || start.starts_with(b"-----BEGIN AGE") {
        return tool("age", format!("age -d {}", quote_path(path)));
    }
    if start.starts_with(b"-----BEGIN PGP") {
        return tool("GPG", format!("gpg -d {}", quote_path(path)));
    }
    let kinds: [(&[u8], &str); 6] = [
        (b"PK\x03\x04", "a zip file"),
        (b"%PDF", "a PDF"),
        (b"\x89PNG", "a PNG image"),
        (b"\xff\xd8\xff", "a JPEG image"),
        (b"\x1f\x8b", "a gzip file"),
        (b"\x7fELF", "a program"),
    ];
    let text = start.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    let kind = kinds.iter().find(|(magic, _)| start.starts_with(magic)).map(|(_, kind)| *kind);
    match kind.or(text.then_some("plain text")) {
        Some(kind) => format!("{shown} isn't encrypted: it's {kind}.\nTo encrypt it:\n  encrypt {}", quote_path(path)),
        None => format!(
            "{shown} wasn't encrypted by this tool: files it encrypts start with AGCM.\n\
             If it should be one, its start has been damaged; try another copy."
        ),
    }
}

pub fn too_short(path: &Path, len: u64, min: u64) -> String {
    format!(
        "{} is only {len} bytes, too short to be an encrypted file (they're at least {min} bytes).\n\
         It has probably been cut short, for example by an interrupted download or copy. Try another copy.",
        safe_path(path)
    )
}

/// An encrypted file whose length doesn't fit the chunks it was written in.
pub fn bad_length(path: &Path) -> String {
    format!(
        "{}'s length doesn't fit how it was encrypted: it was cut short, or something was added to its \
         end.\nNothing was written. Try another copy of it.",
        safe_path(path)
    )
}

/// The start of an encrypted file decrypted, so the key is right, but the
/// chunk at `offset` didn't.
pub fn damaged_from(path: &Path, offset: u64) -> String {
    format!(
        "{} is damaged {} into the file. The key is right, as everything before that decrypted, but \
         from there on the file was changed or cut short after it was encrypted.\nNothing was written. \
         Try another copy of it.",
        safe_path(path),
        fmt_size(offset as usize)
    )
}

pub fn random_failed(e: getrandom::Error) -> String {
    format!(
        "the operating system's random number generator failed: {e}.\nNothing was encrypted. \
         Try again; if it keeps failing, restart the computer."
    )
}

/// A failure part way through encrypting or decrypting `input` into `output`
/// in chunks. `key_file` is the key file used to decrypt, if one was.
pub fn stream_failure(e: stream::Error, input: &Path, output: &Path, key_file: Option<&Path>) -> Error {
    match e {
        stream::Error::Read(e) if e.kind() == io::ErrorKind::UnexpectedEof => Error::File(changed_while_reading(input)),
        stream::Error::Read(e) => Error::File(file(Action::Read, input, &e)),
        stream::Error::Write(e) => Error::File(file(Action::Write, output, &e)),
        stream::Error::Auth(0) => Error::KeyOrData(wrong_key(input, key_file)),
        stream::Error::Auth(n) => Error::KeyOrData(damaged_from(
            input,
            stream::HEADER_LEN as u64 + n * (stream::CHUNK + stream::TAG_LEN) as u64,
        )),
        stream::Error::Truncated => Error::KeyOrData(bad_length(input)),
        stream::Error::Metadata(e) => Error::KeyOrData(e),
        stream::Error::Memory(len) => no_memory(len).into(),
        stream::Error::Random(e) => random_failed(e).into(),
        stream::Error::Interrupted => Error::Interrupted,
    }
}

/// A file that changed while it was being read.
pub fn changed_while_reading(path: &Path) -> String {
    format!(
        "{} changed while it was being read, so something else is writing to it.\nNothing was deleted \
         or replaced. Try again once nothing else is using the file.",
        safe_path(path)
    )
}

/// A file to encrypt that other names (hard links) also lead to.
pub fn other_names(path: &Path, others: u64) -> String {
    let names = if others == 1 { "1 other name".to_string() } else { format!("{others} other names") };
    format!(
        "{} has {names} (hard links) leading to the same contents. Deleting it wouldn't remove \
         them, and overwriting it would leave them as files of zeros, so it wasn't encrypted.\n\
         `find / -xdev -samefile {} 2>/dev/null` lists them. Delete the ones you don't need and \
         encrypt again, or add --keep to encrypt it without deleting anything.",
        safe_path(path),
        quote_path(path)
    )
}

/// A file to encrypt that couldn't be opened for overwriting afterwards.
pub fn cant_overwrite(path: &Path, e: &io::Error) -> String {
    let why = match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => "you don't have permission to write to it".to_string(),
        _ => e.to_string(),
    };
    format!(
        "{} can't be overwritten after encrypting, as {why}, so its contents would stay on the disk. \
         Nothing was encrypted.\nIf it's yours, `ls -lO` (macOS) or `lsattr` (Linux) shows whether \
         it's locked. Otherwise ask its owner to encrypt it, or add --keep to encrypt it without \
         deleting it.",
        safe_path(path)
    )
}

/// The original is on a filesystem that writes changes somewhere new, so
/// overwriting it can't reach its old contents.
pub fn copy_on_write(path: &Path, filesystem: &str) -> String {
    format!(
        "WARNING: {} is on {filesystem}, which writes changes to a new place on the disk instead of over \
         the old data. Overwriting the original after encrypting it won't reach its contents, which stay \
         on the disk until the space is reused, and in any snapshots. Full-disk encryption (FileVault or \
         LUKS) keeps them unreadable without your password.",
        safe_path(path)
    )
}

pub fn unsupported_version(version: u8) -> String {
    if version > crate::VERSION {
        format!(
            "this file was made by a newer version of encryptor (file format {version}; this version \
             reads up to {}).\nUpdate to the latest version, then try again:\n  npm install -g @neddyp/encryptor@latest",
            crate::VERSION
        )
    } else {
        format!("this file's header is damaged: there is no file format {version}. Try another copy.")
    }
}

/// Decryption failed to authenticate: the key is wrong or the file changed.
/// `key_file` is the key file used, if one was.
pub fn wrong_key(input: &Path, key_file: Option<&Path>) -> String {
    let plain = crate::files::decrypted_path(input);
    let plain_name = plain.file_name().unwrap_or_default().to_string_lossy();
    let expected = format!("{plain_name}.key");
    let mut message = format!("{AUTH_FAILED}\nNothing was written.");
    if let Some(used) = key_file {
        let name = used.file_name().unwrap_or_default().to_string_lossy();
        if !(name.starts_with(&format!("{plain_name}.")) && name.ends_with(".key")) {
            message.push_str(&format!(
                "\n- You used the key file {}, but the key for {} is usually {}.",
                safe_path(used),
                safe_path(input),
                safe(&expected)
            ));
        }
    }
    message.push_str(
        "\n- Check it's this file's key: every generated key is different, even for the same file encrypted twice.",
    );
    message.push_str(&format!(
        "\n- If the key is right, {} was changed or damaged after it was encrypted, for example by \
         an incomplete copy or download. Try another copy of it.",
        safe_path(input)
    ));
    message
}

// Key entry. None of these repeat what was typed, unless it's evidently a
// path, since it may be a mistyped key.

pub const EMPTY_KEY: &str =
    "nothing was entered. Paste the 64-character key, or type the path to its key file (such as report.pdf.key).";

pub fn hex_key_length(n: usize) -> String {
    let problem = format!("that key has {n} characters, but keys have exactly 64.");
    match n {
        128 => format!("{problem} It looks like it was pasted twice."),
        _ if n < 64 => format!("{problem} That's {} short: check you copied all of it.", 64 - n),
        _ => format!("{problem} That's {} too many: check nothing else was copied with it.", n - 64),
    }
}

/// Input that is neither a key nor a key file that could be opened.
pub fn not_a_key(input: &str, path: &Path, e: &io::Error) -> String {
    if input.contains(['/', '.', '~']) {
        return match e.kind() {
            io::ErrorKind::NotFound => format!(
                "there's no key file at {}. Key files are saved as FILE.key in the folder encrypt was run in; \
                 `ls *.key` lists the ones in this folder.",
                safe_path(path)
            ),
            _ => file(Action::Read, path, e).replace('\n', " "),
        };
    }
    // Spaces, colons, dashes or a 0x prefix around an otherwise good key.
    let bare: Zeroizing<String> =
        Zeroizing::new(input.chars().filter(|c| !c.is_whitespace() && !matches!(c, ':' | '-')).collect());
    let digits = bare.strip_prefix("0x").or_else(|| bare.strip_prefix("0X")).unwrap_or(&bare);
    if digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut extras = Vec::new();
        if input.contains(char::is_whitespace) {
            extras.push("spaces");
        }
        if input.contains(':') {
            extras.push("colons");
        }
        if input.contains('-') {
            extras.push("dashes");
        }
        if digits.len() < bare.len() {
            extras.push("a 0x at the start");
        }
        return format!(
            "that key has {} in it. Enter just its 64 characters of 0-9 and a-f.",
            listed(&extras)
        );
    }
    // Nearly a key: point to the first character that doesn't belong.
    if (56..=72).contains(&input.chars().count()) {
        if let Some((i, c)) = input.chars().enumerate().find(|(_, c)| !c.is_ascii_hexdigit()) {
            let what = match c {
                'o' | 'O' => "the letter O, where keys would have the digit 0",
                'l' | 'I' => "a letter that looks like 1, where keys would have the digit 1",
                c if c.is_alphabetic() => "a letter after f",
                _ => "not 0-9 or a-f",
            };
            return format!("that isn't a valid key: character {} is {what}. Keys only use 0-9 and a-f.", i + 1);
        }
    }
    "that isn't a key or a key file. A key is 64 characters of 0-9 and a-f, as printed by encrypt; \
     a key file is a path such as report.pdf.key."
        .into()
}

pub fn key_file_size(path: &Path, size: u64) -> String {
    let shown = safe_path(path);
    if path.extension().is_some_and(|ext| ext == "enc") {
        return format!(
            "{shown} is an encrypted file, not a key. Its key file is usually {}.",
            safe_path(&path.with_extension("key"))
        );
    }
    match size {
        0 => format!("{shown} is empty, so it isn't a key file. Key files hold 32 bytes, or 64 hex characters."),
        _ => format!(
            "{shown} is {size} bytes, but key files hold exactly 32 bytes, or 64 hex characters. Check it's \
             the .key file saved when the file was encrypted."
        ),
    }
}

/// A decrypted file that would replace one already there, in a script.
pub fn needs_overwrite(output: &Path) -> String {
    format!(
        "{} already exists. Add --overwrite to replace it, or --output to write somewhere else.\n\
         Replacing a file is never agreed to through a pipe, since the answer could be meant for \
         another question.",
        safe_path(output)
    )
}

pub fn key_file_folder(path: &Path) -> String {
    format!("{} is a folder, not a key file. Give the path of the .key file inside it.", safe_path(path))
}

/// "a", "a and b", "a, b and c".
pub fn listed(items: &[&str]) -> String {
    match items.split_last() {
        Some((last, [])) => last.to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    }
}

/// The folder a path is in, as given.
fn folder(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn folder_name(folder: &Path) -> String {
    if folder == Path::new(".") { "the current folder".into() } else { safe_path(folder) }
}

fn look_here() -> String {
    let here = std::env::current_dir().map_or_else(|_| "unknown".into(), |dir| safe_path(&dir));
    format!("Check the spelling. Paths start from the current folder ({here}); `ls` lists what's in it.")
}

/// Another file in the same folder whose name differs only in capitals.
fn same_name_but_case(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let found = fs::read_dir(folder(path)).ok()?.flatten().map(|entry| entry.file_name()).find(|other| {
        other != name && other.as_encoded_bytes().eq_ignore_ascii_case(name.as_encoded_bytes())
    })?;
    Some(path.with_file_name(found))
}

fn join(problem: String, fix: &str) -> String {
    if fix.is_empty() { problem } else { format!("{problem}\n{fix}") }
}

/// Quotes `s` for the shell when it needs it, and makes it safe to print.
pub fn quote(s: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"._-/+=:@%,".contains(&b);
    if !s.is_empty() && s.bytes().all(plain) {
        safe(s)
    } else {
        safe(&format!("'{}'", s.replace('\'', r"'\''")))
    }
}

fn quote_path(path: &Path) -> String {
    quote(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encryptor-explain-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn os_error(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn explains_file_errors_with_a_fix() {
        let path = Path::new("/media/usb/report.pdf.enc");
        let full = file(Action::Write, path, &os_error(libc::ENOSPC));
        assert_eq!(
            full,
            "cannot write /media/usb/report.pdf.enc: the disk is full.\n\
             Free up some space and try again. `df -h /media/usb` shows how much is free."
        );
        assert!(file(Action::Write, path, &os_error(libc::EFBIG)).contains("FAT32"));
        assert!(file(Action::Create, path, &os_error(libc::EROFS)).contains("/media/usb is on a read-only disk"));
        assert!(file(Action::Create, path, &os_error(libc::EACCES)).contains("change files in /media/usb"));
        let read = file(Action::Read, Path::new("my file"), &os_error(libc::EACCES));
        assert!(read.contains("permission to read it") && read.contains("`ls -l 'my file'`"), "{read}");
        assert!(file(Action::Create, Path::new("x"), &os_error(libc::EACCES)).contains("the current folder"));
        assert_eq!(cause(Action::Delete, path, &os_error(libc::EIO)), "the disk reported an error");
    }

    #[test]
    fn suggests_the_file_that_was_probably_meant() {
        let dir = scratch("missing");
        fs::write(dir.join("report.pdf.enc"), b"x").unwrap();
        fs::write(dir.join("Notes.txt"), b"x").unwrap();
        let gone = os_error(libc::ENOENT);

        let decrypt = missing("decrypt", &dir.join("report.pdf"), &gone);
        assert!(decrypt.contains("Did you mean the encrypted file?") && decrypt.ends_with("report.pdf.enc"));
        let encrypt = missing("encrypt", &dir.join("report.pdf"), &gone);
        assert!(encrypt.contains("It may be encrypted already"), "{encrypt}");
        let case = missing("encrypt", &dir.join("notes.txt"), &gone);
        assert!(case.contains("Did you mean") && case.ends_with("Notes.txt"), "{case}");
        let neither = missing("encrypt", &dir.join("other"), &gone);
        assert!(neither.contains("Check the spelling"), "{neither}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn points_links_to_the_real_file() {
        let dir = scratch("link");
        fs::write(dir.join("real.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("real.txt"), dir.join("link")).unwrap();
        std::os::unix::fs::symlink(dir.join("gone"), dir.join("broken")).unwrap();
        let real = fs::canonicalize(dir.join("real.txt")).unwrap();

        assert!(symlink("encrypt", &dir.join("link")).ends_with(&format!("encrypt {}", real.display())));
        assert!(symlink("encrypt", &dir.join("broken")).contains("which doesn't exist"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tells_what_an_unencrypted_file_is() {
        let path = Path::new("photo.jpg");
        assert!(not_encrypted(path, b"\xff\xd8\xff\xe0").contains("isn't encrypted: it's a JPEG image"));
        assert!(not_encrypted(path, b"PK\x03\x04").ends_with("encrypt photo.jpg"));
        assert!(not_encrypted(path, b"hello, world\n").contains("it's plain text"));
        assert!(not_encrypted(path, b"Salted__12345678").contains("encrypted with OpenSSL"));
        assert!(not_encrypted(path, b"age-encryption.org/v1").contains("age -d photo.jpg"));
        assert!(not_encrypted(path, b"-----BEGIN PGP MESSAGE").contains("gpg -d photo.jpg"));
        assert!(not_encrypted(path, b"\x00\x01\x02").contains("start with AGCM"));
        assert!(not_encrypted(path, b"").contains("is empty"));
        let key = not_encrypted(Path::new("photo.jpg.key"), &[7; 32]);
        assert!(key.contains("is a key file") && key.ends_with("decrypt photo.jpg.enc"), "{key}");
    }

    #[test]
    fn notices_a_key_file_for_another_file() {
        let input = Path::new("report.pdf.enc");
        let other = wrong_key(input, Some(Path::new("photo.jpg.key")));
        assert!(other.contains("You used the key file photo.jpg.key, but the key for report.pdf.enc is usually report.pdf.key"));
        for right in ["report.pdf.key", "report.pdf.2.key"] {
            assert!(!wrong_key(input, Some(Path::new(right))).contains("You used"), "{right}");
        }
        assert!(wrong_key(input, None).contains("Try another copy"));
    }

    #[test]
    fn explains_key_mistakes() {
        assert!(hex_key_length(63).contains("That's 1 short"));
        assert!(hex_key_length(128).contains("pasted twice"));
        assert!(hex_key_length(70).contains("That's 6 too many"));
        assert!(key_file_size(Path::new("report.pdf.enc"), 1000).contains("usually report.pdf.key"));
        assert!(key_file_size(Path::new("k.txt"), 65).contains("or 64 hex characters"));
        assert!(key_file_size(Path::new("k.key"), 0).contains("is empty"));
    }

    #[test]
    fn suggests_commands_with_the_names_given() {
        let dir = scratch("commands");
        let file = dir.join("data.enc");
        fs::write(&file, b"x").unwrap();
        let named = unknown_command(file.to_str().unwrap(), "USAGE");
        assert!(named.contains("is a file, not a command") && named.contains("decrypt "), "{named}");
        assert!(unknown_command("--force", "USAGE").starts_with("unknown option '--force'. These are the options"));
        assert!(unknown_command("crypt", "USAGE").starts_with("unknown command 'crypt'"));
        fs::remove_dir_all(&dir).unwrap();

        assert!(decrypt_folder(Path::new("My Files/")).ends_with("for f in 'My Files'/*.enc; do decrypt \"$f\"; done"));
        let several = decrypt_one_at_a_time(&["a.enc".into(), "b c.enc".into()]);
        assert!(several.ends_with("for f in a.enc 'b c.enc'; do decrypt \"$f\"; done"), "{several}");
        assert!(output_exists(Path::new("report.pdf.enc")).ends_with("mv report.pdf.enc report.pdf.old.enc"));
    }

    #[test]
    fn explains_how_to_zip_a_folder() {
        let message = zip_instead(&["Holiday photos/".into()]);
        assert!(message.starts_with("Holiday photos/ is a folder.\n"), "{message}");
        assert!(message.contains("Zip the folder:    zip -r 'Holiday photos.zip' 'Holiday photos/'\n"));
        assert!(message.contains("Encrypt the zip:   encrypt 'Holiday photos.zip'\n"));
    }

    #[test]
    fn explains_how_to_zip_several_files() {
        let message = zip_instead(&["a.txt".into(), "it's.pdf".into()]);
        assert!(message.starts_with("encrypt was given 2 files.\n"), "{message}");
        assert!(message.contains(r"Zip the files:     zip -r files.zip a.txt 'it'\''s.pdf'"));
        assert!(message.contains("Zip a folder:      zip -r folder.zip FOLDER\n"));
        assert!(message.contains("Encrypt the zip:   encrypt files.zip\n"));

        let many: Vec<String> = (0..20).map(|i| format!("file-{i}.txt")).collect();
        assert!(zip_instead(&many).contains("zip -r files.zip FILE1 FILE2 ...\n"));
    }

    #[test]
    fn quotes_names_for_pasting() {
        assert_eq!(quote("report.pdf"), "report.pdf");
        assert_eq!(quote("my report.pdf"), "'my report.pdf'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("evil\x1b[2J"), "'evil\\u{1b}[2J'");
        assert_eq!(listed(&["a", "b", "c"]), "a, b and c");
    }
}
