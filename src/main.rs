//! encryptor: interactive AES-256-GCM file encryption and decryption.
//!
//! Files are written in format version 3, encrypted in 64 KiB chunks (see
//! `stream`). Versions 1 and 2, which encrypted the whole file at once, are
//! still read (see `legacy`). From version 2 the plaintext starts with the
//! original file's metadata (see `meta`).

mod art;
mod batch;
mod cli;
mod decrypt;
mod desktop;
mod encrypt;
mod error;
mod explain;
mod files;
mod history;
mod home;
mod kdf;
mod keys;
mod legacy;
mod meta;
mod pager;
mod progress;
mod protect;
mod recording;
mod report;
mod session;
mod stream;
mod term;
#[cfg(test)]
mod testing;
mod update;
mod view;
mod wipe;

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use cli::Command;
use error::Result;

const MAGIC: &[u8; 4] = b"AGCM";
/// The newest format version read. Version 3 is written for a key, and 4
/// for a passphrase.
const VERSION: u8 = stream::PASSPHRASE_VERSION;
const KEY_LEN: usize = 32;

#[global_allocator]
static ALLOCATOR: protect::ZeroOnFree = protect::ZeroOnFree;

const USAGE: &str = "\
encryptor - encrypt and decrypt files with AES-256-GCM

USAGE:
    encrypt FILE... [OPTIONS]      encrypt each FILE to FILE.enc, then delete it
    encrypt -r FOLDER [OPTIONS]    encrypt every file in FOLDER and its subfolders
    decrypt FILE.enc... [OPTIONS]  decrypt each FILE.enc back to FILE
    decrypt -r FOLDER [OPTIONS]    decrypt every .enc file in FOLDER and its
                                   subfolders, all with one key
    encryptor view FILE.enc        show FILE.enc decrypted on screen, erase
                                   it, then keep its key or change it
    encryptor                      show the home screen
    encryptor update               update to the latest release

`encryptor encrypt FILE` and `encryptor decrypt FILE` do the same as encrypt
and decrypt, and `encryptor -v FILE.enc` as view. Anything not given is
asked for. With several files, you're asked whether to use one universal key
for them all, saved as FOLDER.key after their folder, or a separate key for
each. --key-file and --new-key give one key for them all.

OPTIONS:
    -r, --recursive       take in every file in the folders given, and in
                          their subfolders; decrypt takes .enc files only
    -k, --key-file KEY    use the key in KEY: 32 bytes, or 64 hex characters.
                          KEY can be a pipe, as in <(pass show keys/report)
        --new-key PATH    encrypt with a new key, saved to PATH, or into PATH
                          if it's a folder
        --keep            encrypt: keep the original instead of deleting it
    -o, --output PATH     decrypt: write the decrypted file to PATH
    -v, --view            view the file, instead of decrypting it to disk
        --overwrite       decrypt: replace the output if it already exists
    -y, --yes             don't ask to confirm encrypting or decrypting
    -q, --quiet           don't print the report
    -h, --help            show this help
    -V, --version         show the version and the file formats it reads

Without a terminal, as in scripts, use options rather than piping answers
in: piped answers still work, but stop in 3.0.

EXIT STATUS:
    0 success, 2 bad options, 3 wrong key or damaged file,
    4 file problem (missing, no permission, disk full), 1 anything else,
    130 interrupted
";

fn main() -> ExitCode {
    protect::harden_process();

    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let Ok(mut args) = args.map(OsString::into_string).collect::<std::result::Result<Vec<_>, _>>() else {
        eprintln!("\nerror: a name on the command line isn't valid UTF-8 text, which this tool can't read.");
        eprintln!("Rename the file using ordinary letters and numbers, then try again.");
        return ExitCode::from(2);
    };

    // At a terminal, whatever the command, the run has a screen of its own,
    // wiped when it ends.
    let session = session::start(version());

    // Started as `encrypt` or `decrypt`, the name is the command.
    let name = Path::new(&program).file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if matches!(name, "encrypt" | "decrypt") {
        args.insert(0, name.to_owned());
    }

    let result = run(&args);
    protect::scrub_stack();
    let code = match &result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => ExitCode::from(e.exit_code()),
    };
    match session {
        // Errors are shown on the run's screen, and go with it.
        Some(session) => session.finish(&result),
        None => match result {
            Err(e @ error::Error::Interrupted) => eprintln!("\n{e}"),
            Err(e) => eprintln!("\nerror: {e}"),
            Ok(()) => {}
        },
    }
    code
}

fn run(args: &[String]) -> Result<()> {
    let invocation = cli::parse(args, USAGE)?;
    let command = match invocation.command {
        // On its own screen, the help is the home screen's, which scrolls.
        Command::Help if session::active() => match choose_at_home()? {
            Some(command) => command,
            None => return Ok(()),
        },
        Command::Help => {
            print!("{USAGE}");
            return Ok(());
        }
        Command::Version => {
            println!("{}", version());
            return Ok(());
        }
        Command::Choose if home::available() => match choose_at_home()? {
            Some(command) => command,
            None => return Ok(()),
        },
        // Without a terminal, as in old scripts, ask the old way.
        Command::Choose => match term::choose("Encrypt or decrypt?", &["encrypt", "decrypt"])? {
            "encrypt" => Command::Encrypt,
            _ => Command::Decrypt,
        },
        command => command,
    };
    let options = &invocation.options;
    cli::check(command, options)?;
    let files = &invocation.files;
    let file = files.first().map(String::as_str);
    // Several files, or folders with -r, are a batch.
    let batch = files.len() > 1 || options.recursive;
    match command {
        Command::Encrypt if batch => batch::encrypt(files, options),
        Command::Encrypt => encrypt::command(file, options),
        Command::View => view::command(file, options),
        Command::Update => update::command(),
        _ if batch => batch::decrypt(files, options),
        _ => decrypt::command(file, options),
    }
}

/// Shows the home screen and returns the command chosen, with the art drawn
/// again at the top for it, or `None` to quit, which ends the run at once.
fn choose_at_home() -> Result<Option<Command>> {
    let command = match home::show(USAGE, &version())? {
        home::Choice::Encrypt => Command::Encrypt,
        home::Choice::Decrypt => Command::Decrypt,
        home::Choice::View => Command::View,
        home::Choice::Quit => {
            session::close_now();
            return Ok(None);
        }
    };
    session::header();
    Ok(Some(command))
}

fn version() -> String {
    format!(
        "encryptor {}, writing file formats {} and {VERSION} and reading formats 1 to {VERSION}",
        env!("CARGO_PKG_VERSION"),
        stream::VERSION
    )
}
