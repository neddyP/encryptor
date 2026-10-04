//! The command line: which command, which file, and options that answer the
//! command's questions in advance, so scripts never answer them by position.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::explain;

/// Answers given on the command line. A question whose option is given isn't
/// asked.
#[derive(Default)]
pub struct Options {
    /// Use the key in this file instead of asking for one.
    pub key_file: Option<PathBuf>,
    /// Encrypt with a new key, saved to this file, or into this folder.
    pub new_key: Option<PathBuf>,
    /// Keep the original after encrypting it.
    pub keep: bool,
    /// Write the decrypted file here instead of next to the encrypted one.
    pub output: Option<PathBuf>,
    /// Replace the decrypted file if it already exists.
    pub overwrite: bool,
    /// Don't ask to confirm encrypting or decrypting.
    pub yes: bool,
    /// Don't print the report.
    pub quiet: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Command {
    Help,
    Version,
    Encrypt,
    Decrypt,
    /// None given: ask which.
    Choose,
}

pub struct Invocation {
    pub command: Command,
    pub file: Option<String>,
    pub options: Options,
}

/// Reads the arguments, with the command first when there is one. Options can
/// come before or after the file, and `--` ends them, for a file whose name
/// starts with `-`.
pub fn parse(args: &[String], usage: &str) -> Result<Invocation> {
    let mut options = Options::default();
    let (mut help, mut version) = (false, false);
    let mut words = Vec::new();
    let mut args = args.iter();
    let mut only_words = false;

    while let Some(arg) = args.next() {
        if only_words || !arg.starts_with('-') || arg == "-" {
            words.push(arg.clone());
            continue;
        }
        if arg == "--" {
            only_words = true;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if arg.starts_with("--") => (name, Some(value)),
            _ => (arg.as_str(), None),
        };
        let mut path = || match inline {
            Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
            Some(_) => Err(Error::Usage(format!("{name} needs a path after it"))),
            None => args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| Error::Usage(format!("{name} needs a path after it"))),
        };
        match name {
            "-k" | "--key-file" => options.key_file = Some(path()?),
            "--new-key" => options.new_key = Some(path()?),
            "-o" | "--output" => options.output = Some(path()?),
            "-h" | "--help" | "-V" | "--version" | "--keep" | "--overwrite" | "-y" | "--yes" | "-q" | "--quiet"
                if inline.is_some() =>
            {
                return Err(Error::Usage(format!("{name} doesn't take a value")));
            }
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            "--keep" => options.keep = true,
            "--overwrite" => options.overwrite = true,
            "-y" | "--yes" => options.yes = true,
            "-q" | "--quiet" => options.quiet = true,
            _ => return Err(Error::Usage(explain::unknown_command(name, usage))),
        }
    }

    let mut words = words.into_iter();
    let command = match words.as_slice().first().map(String::as_str) {
        _ if help => Command::Help,
        _ if version => Command::Version,
        Some("help") => Command::Help,
        Some("version") => Command::Version,
        Some("encrypt" | "enc" | "e") => Command::Encrypt,
        Some("decrypt" | "dec" | "d") => Command::Decrypt,
        Some(other) => return Err(Error::Usage(explain::unknown_command(other, usage))),
        None => Command::Choose,
    };
    words.next();
    let files: Vec<String> = words.collect();
    if matches!(command, Command::Help | Command::Version) {
        return Ok(Invocation { command, file: None, options });
    }
    if files.len() > 1 {
        return Err(Error::Usage(match command {
            Command::Decrypt => explain::decrypt_one_at_a_time(&files),
            _ => explain::zip_instead(&files),
        }));
    }
    Ok(Invocation { command, file: files.into_iter().next(), options })
}

/// Fails if an option doesn't apply to `command`, or two conflict.
pub fn check(command: Command, options: &Options) -> Result<()> {
    let only = |option: &str, applies: &str| {
        Err(Error::Usage(format!("{option} only applies to {applies}; see encryptor --help")))
    };
    if options.key_file.is_some() && options.new_key.is_some() {
        return Err(Error::Usage(
            "--key-file and --new-key can't be used together: encrypt with an existing key or a new one".into(),
        ));
    }
    match command {
        Command::Encrypt if options.output.is_some() => only("--output", "decrypt"),
        Command::Encrypt if options.overwrite => only("--overwrite", "decrypt"),
        Command::Decrypt if options.new_key.is_some() => only("--new-key", "encrypt"),
        Command::Decrypt if options.keep => only("--keep", "encrypt, which deletes the original; decrypt keeps it anyway"),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Invocation> {
        parse(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>(), "USAGE")
    }

    fn usage_error(result: Result<Invocation>) -> String {
        match result {
            Err(Error::Usage(e)) => e,
            _ => panic!("expected a usage error"),
        }
    }

    #[test]
    fn reads_options_anywhere() {
        let run = parsed(&["encrypt", "--keep", "report.pdf", "--new-key", "k.key", "-y"]).unwrap();
        assert!(run.command == Command::Encrypt);
        assert_eq!(run.file.as_deref(), Some("report.pdf"));
        assert_eq!(run.options.new_key, Some(PathBuf::from("k.key")));
        assert!(run.options.keep && run.options.yes && !run.options.quiet);

        let run = parsed(&["decrypt", "--key-file=k.key", "-o", "out.pdf", "--overwrite", "a.enc"]).unwrap();
        assert!(run.command == Command::Decrypt);
        assert_eq!(run.options.key_file, Some(PathBuf::from("k.key")));
        assert_eq!(run.options.output, Some(PathBuf::from("out.pdf")));
        assert!(run.options.overwrite);
    }

    #[test]
    fn takes_names_after_a_double_dash() {
        let run = parsed(&["encrypt", "--", "-odd name"]).unwrap();
        assert_eq!(run.file.as_deref(), Some("-odd name"));
    }

    #[test]
    fn answers_help_and_version_before_anything_else() {
        assert!(parsed(&["encrypt", "a", "b", "--help"]).unwrap().command == Command::Help);
        assert!(parsed(&["-V"]).unwrap().command == Command::Version);
        assert!(parsed(&["version"]).unwrap().command == Command::Version);
        assert!(parsed(&[]).unwrap().command == Command::Choose);
    }

    #[test]
    fn rejects_bad_command_lines() {
        assert!(usage_error(parsed(&["encrypt", "--key-file"])).contains("needs a path"));
        assert!(usage_error(parsed(&["encrypt", "--key-file="])).contains("needs a path"));
        assert!(usage_error(parsed(&["encrypt", "--yes=no", "f"])).contains("doesn't take a value"));
        assert!(usage_error(parsed(&["encrypt", "--force", "f"])).contains("unknown option '--force'"));
        assert!(usage_error(parsed(&["encrypt", "a", "b"])).contains("encrypt was given 2 files"));
        assert!(usage_error(parsed(&["decrypt", "a", "b"])).contains("decrypt was given 2 files"));

        let both = Options { key_file: Some("a".into()), new_key: Some("b".into()), ..Options::default() };
        assert!(matches!(check(Command::Encrypt, &both), Err(Error::Usage(_))));
        let keep = Options { keep: true, ..Options::default() };
        assert!(matches!(check(Command::Decrypt, &keep), Err(Error::Usage(_))));
        let output = Options { output: Some("o".into()), ..Options::default() };
        assert!(matches!(check(Command::Encrypt, &output), Err(Error::Usage(_))));
        assert!(check(Command::Decrypt, &output).is_ok());
    }
}
