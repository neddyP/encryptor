//! encryptor: interactive AES-256-GCM file encryption and decryption.
//!
//! Files are written in format version 3, encrypted in 64 KiB chunks (see
//! `stream`). Versions 1 and 2, which encrypted the whole file at once, are
//! still read (see `legacy`). From version 2 the plaintext starts with the
//! original file's metadata (see `meta`).

mod cli;
mod decrypt;
mod desktop;
mod encrypt;
mod error;
mod explain;
mod files;
mod history;
mod home;
mod keys;
mod legacy;
mod meta;
mod protect;
mod recording;
mod report;
mod session;
mod stream;
mod term;
mod timestamps;
mod update;
mod wipe;

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use cli::Command;
use error::Result;

const MAGIC: &[u8; 4] = b"AGCM";
/// The newest format version, which is the one written.
const VERSION: u8 = stream::VERSION;
const KEY_LEN: usize = 32;

#[global_allocator]
static ALLOCATOR: protect::ZeroOnFree = protect::ZeroOnFree;

const USAGE: &str = "\
encryptor - encrypt and decrypt files with AES-256-GCM

USAGE:
    encrypt FILE [OPTIONS]         encrypt FILE to FILE.enc, then delete FILE
    decrypt FILE.enc [OPTIONS]     decrypt FILE.enc back to FILE
    encryptor                      show the home screen, to encrypt or decrypt
    encryptor update               update to the latest release

`encryptor encrypt FILE` and `encryptor decrypt FILE` do the same as encrypt
and decrypt. Anything not given is asked for.

OPTIONS:
    -k, --key-file KEY    use the key in KEY: 32 bytes, or 64 hex characters.
                          KEY can be a pipe, as in <(pass show keys/report)
        --new-key PATH    encrypt with a new key, saved to PATH, or into PATH
                          if it's a folder
        --keep            encrypt: keep the original instead of deleting it
    -o, --output PATH     decrypt: write the decrypted file to PATH
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

To encrypt a folder or several files, zip them into one file first:
    zip -r photos.zip photos
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
    match name {
        "encrypt" | "decrypt" => args.insert(0, name.to_owned()),
        "aes256" => eprintln!("note: the aes256 command is now called encryptor; aes256 will be removed in 3.0."),
        _ => {}
    }

    let result = run(&args);
    // Whatever happened, including a typo or --help, the command that ran
    // this shouldn't stay in shell history. Most runs have already done this,
    // and say so in the report.
    let _ = history::clean(None);
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
    // Last, once nothing more will be read: the program's files shouldn't
    // show when it ran.
    timestamps::reset();
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
    cli::check(command, &invocation.options)?;
    let file = invocation.file.as_deref();
    match command {
        Command::Encrypt => encrypt::command(file, &invocation.options),
        Command::Update => update::command(),
        _ => decrypt::command(file, &invocation.options),
    }
}

/// Shows the home screen and returns the command chosen, with the art drawn
/// again at the top for it, or `None` to quit, which ends the run at once.
fn choose_at_home() -> Result<Option<Command>> {
    let command = match home::show(USAGE, &version())? {
        home::Choice::Encrypt => Command::Encrypt,
        home::Choice::Decrypt => Command::Decrypt,
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
        "encryptor {}, writing file format {VERSION} and reading formats 1 to {VERSION}",
        env!("CARGO_PKG_VERSION")
    )
}
