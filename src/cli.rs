//! The command line: which command, which files, and options that answer the
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
    /// Take in every file in the folders given, and in their subfolders.
    pub recursive: bool,
    /// Name each .enc file with 16 random bytes, keeping the real name in
    /// its folder's .encryptor file and in the filenames folder.
    pub hide_names: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Command {
    Help,
    Version,
    Encrypt,
    Decrypt,
    /// Show the file decrypted, then encrypt it again.
    View,
    Update,
    /// None given: ask which.
    Choose,
}

pub struct Invocation {
    pub command: Command,
    /// The files and folders given, in order.
    pub files: Vec<String>,
    pub options: Options,
}

/// Options that take a value, in the next word.
const TAKE_VALUES: [&str; 5] = ["-k", "-o", "--key-file", "--new-key", "--output"];

/// Splits short options stacked in one word, as `-rn` for `-r -n`, into one
/// word each. One that takes a value, -k or -o, takes the rest of the word as
/// it, as in `-kKEY`, or else the next word, as it would on its own. Words
/// after `--`, and values, are left as they are.
fn unstack(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let (mut only_words, mut value_next) = (false, false);
    for arg in args {
        let stacked = !only_words && !value_next && arg.starts_with('-') && !arg.starts_with("--");
        if !stacked || arg.chars().count() <= 2 {
            value_next = !only_words && !value_next && TAKE_VALUES.contains(&arg.as_str());
            only_words |= arg == "--" && !value_next;
            out.push(arg.clone());
            continue;
        }
        let mut letters = arg.chars().skip(1);
        while let Some(letter) = letters.next() {
            out.push(format!("-{letter}"));
            if matches!(letter, 'k' | 'o') {
                let rest: String = letters.collect();
                match rest.is_empty() {
                    true => value_next = true,
                    false => out.push(rest),
                }
                break;
            }
        }
    }
    out
}

/// Reads the arguments, with the command first when there is one. Options can
/// come before or after the file, short ones stacked or not (`-rn` is
/// `-r -n`), and `--` ends them, for a file whose name starts with `-`.
pub fn parse(args: &[String], usage: &str) -> Result<Invocation> {
    let mut options = Options::default();
    let (mut help, mut version, mut view) = (false, false, false);
    let mut words = Vec::new();
    let args = unstack(args);
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
            "-h" | "--help" | "-V" | "--version" | "-v" | "--view" | "--keep" | "--overwrite" | "-y" | "--yes"
            | "-q" | "--quiet" | "-r" | "--recursive" | "-n" | "--hide-names"
                if inline.is_some() =>
            {
                return Err(Error::Usage(format!("{name} doesn't take a value")));
            }
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            "-v" | "--view" => view = true,
            "--keep" => options.keep = true,
            "--overwrite" => options.overwrite = true,
            "-y" | "--yes" => options.yes = true,
            "-q" | "--quiet" => options.quiet = true,
            "-r" | "--recursive" => options.recursive = true,
            "-n" | "--hide-names" => options.hide_names = true,
            _ => return Err(Error::Usage(explain::unknown_command(name, usage))),
        }
    }

    let first = words.first().map(String::as_str);
    let named = first.and_then(named);
    let command = match (named, first) {
        _ if help => Command::Help,
        _ if version => Command::Version,
        // -v views the file, where decrypt would write it out. Without a
        // command, every word is a file.
        (Some(Command::View | Command::Decrypt) | None, _) if view => Command::View,
        (Some(_), Some(other)) if view => {
            return Err(Error::Usage(format!("-v (view) can't be used with {other}. For the version, use -V.")));
        }
        (Some(command), _) => command,
        (None, Some(other)) => return Err(Error::Usage(explain::unknown_command(other, usage))),
        (None, None) => Command::Choose,
    };
    let files: Vec<String> = words.into_iter().skip(usize::from(named.is_some())).collect();
    if matches!(command, Command::Help | Command::Version) {
        return Ok(Invocation { command, files: Vec::new(), options });
    }
    if command == Command::Update && !files.is_empty() {
        return Err(Error::Usage("update doesn't take a file. Run it on its own: encryptor update".into()));
    }
    if command == Command::View && files.len() > 1 {
        return Err(Error::Usage(format!("view was given {} files; it shows one at a time.", files.len())));
    }
    if options.output.is_some() && (files.len() > 1 || options.recursive) {
        return Err(Error::Usage(
            "--output names one decrypted file. With several, each is decrypted next to its .enc file.".into(),
        ));
    }
    Ok(Invocation { command, files, options })
}

/// The command a word names, if it names one.
fn named(word: &str) -> Option<Command> {
    match word {
        "help" => Some(Command::Help),
        "version" => Some(Command::Version),
        "encrypt" | "enc" | "e" => Some(Command::Encrypt),
        "decrypt" | "dec" | "d" => Some(Command::Decrypt),
        "view" | "v" => Some(Command::View),
        "update" => Some(Command::Update),
        _ => None,
    }
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
    let any = options.key_file.is_some()
        || options.new_key.is_some()
        || options.output.is_some()
        || options.keep
        || options.overwrite
        || options.yes
        || options.quiet
        || options.recursive
        || options.hide_names;
    match command {
        Command::Update if any => {
            Err(Error::Usage("update doesn't take options. Run it on its own: encryptor update".into()))
        }
        Command::Encrypt if options.output.is_some() => only("--output", "decrypt"),
        Command::Encrypt if options.overwrite => only("--overwrite", "decrypt"),
        Command::Decrypt if options.new_key.is_some() => only("--new-key", "encrypt"),
        Command::Decrypt if options.hide_names => Err(Error::Usage(
            "--hide-names only applies to encrypt: decrypt gives files their real names back by itself".into(),
        )),
        Command::Decrypt if options.keep => {
            Err(Error::Usage(
                "--keep only applies to encrypt: decrypt always shreds the encrypted file once it's decrypted and \
                 verified"
                    .into(),
            ))
        }
        Command::View
            if options.new_key.is_some()
                || options.output.is_some()
                || options.keep
                || options.overwrite
                || options.yes
                || options.recursive
                || options.hide_names =>
        {
            Err(Error::Usage("view only takes --key-file and --quiet; it asks everything else at the keyboard".into()))
        }
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
        assert_eq!(run.files, ["report.pdf"]);
        assert_eq!(run.options.new_key, Some(PathBuf::from("k.key")));
        assert!(run.options.keep && run.options.yes && !run.options.quiet);

        let run = parsed(&["decrypt", "--key-file=k.key", "-o", "out.pdf", "--overwrite", "a.enc"]).unwrap();
        assert!(run.command == Command::Decrypt);
        assert_eq!(run.options.key_file, Some(PathBuf::from("k.key")));
        assert_eq!(run.options.output, Some(PathBuf::from("out.pdf")));
        assert!(run.options.overwrite);
    }

    #[test]
    fn takes_short_options_stacked() {
        let run = parsed(&["encrypt", "-rn", "docs", "-yq"]).unwrap();
        let o = &run.options;
        assert!(o.recursive && o.hide_names && o.yes && o.quiet);
        assert_eq!(run.files, ["docs"]);
        // A value comes from the rest of the word, or the next.
        let run = parsed(&["decrypt", "-rk", "k.key", "docs"]).unwrap();
        assert!(run.options.recursive);
        assert_eq!(run.options.key_file, Some(PathBuf::from("k.key")));
        assert_eq!(run.files, ["docs"]);
        let run = parsed(&["decrypt", "-ykk.key", "a.enc"]).unwrap();
        assert!(run.options.yes);
        assert_eq!(run.options.key_file, Some(PathBuf::from("k.key")));
        // A value starting with - isn't taken apart, nor anything after --.
        let run = parsed(&["decrypt", "-k", "-rn.key", "a.enc"]).unwrap();
        assert_eq!(run.options.key_file, Some(PathBuf::from("-rn.key")));
        assert!(!run.options.recursive);
        let run = parsed(&["encrypt", "--", "-rn"]).unwrap();
        assert_eq!(run.files, ["-rn"]);
        assert!(!run.options.recursive);
        assert!(usage_error(parsed(&["encrypt", "-rx", "docs"])).contains("unknown option '-x'"));
        assert!(parsed(&["-Vr"]).unwrap().command == Command::Version);
    }

    #[test]
    fn takes_names_after_a_double_dash() {
        let run = parsed(&["encrypt", "--", "-odd name"]).unwrap();
        assert_eq!(run.files, ["-odd name"]);
    }

    #[test]
    fn answers_help_and_version_before_anything_else() {
        assert!(parsed(&["encrypt", "a", "b", "--help"]).unwrap().command == Command::Help);
        assert!(parsed(&["-V"]).unwrap().command == Command::Version);
        assert!(parsed(&["version"]).unwrap().command == Command::Version);
        assert!(parsed(&[]).unwrap().command == Command::Choose);
    }

    #[test]
    fn views_with_a_command_or_a_flag() {
        let views: [&[&str]; 5] =
            [&["view", "a.enc"], &["v", "a.enc"], &["-v", "a.enc"], &["a.enc", "--view"], &["decrypt", "-v", "a.enc"]];
        for args in views {
            let run = parsed(args).unwrap_or_else(|_| panic!("{args:?}"));
            assert!(run.command == Command::View, "{args:?}");
            assert_eq!(run.files, ["a.enc"], "{args:?}");
        }
        assert!(parsed(&["-v"]).unwrap().command == Command::View);
        assert!(parsed(&["view"]).unwrap().files.is_empty());
        assert!(usage_error(parsed(&["encrypt", "-v", "a"])).contains("can't be used with encrypt"));
        assert!(usage_error(parsed(&["--view=x", "a"])).contains("doesn't take a value"));
        assert!(usage_error(parsed(&["view", "a", "b"])).contains("view was given 2 files"));

        let key = Options { key_file: Some("k".into()), quiet: true, ..Options::default() };
        assert!(check(Command::View, &key).is_ok());
        for refused in [
            Options { yes: true, ..Options::default() },
            Options { output: Some("o".into()), ..Options::default() },
            Options { new_key: Some("n".into()), ..Options::default() },
            Options { keep: true, ..Options::default() },
            Options { overwrite: true, ..Options::default() },
            Options { recursive: true, ..Options::default() },
        ] {
            assert!(matches!(check(Command::View, &refused), Err(Error::Usage(_))));
        }
    }

    #[test]
    fn takes_several_files_and_folders() {
        let run = parsed(&["encrypt", "a.pdf", "b.md", "c.xlsx"]).unwrap();
        assert!(run.command == Command::Encrypt && !run.options.recursive);
        assert_eq!(run.files, ["a.pdf", "b.md", "c.xlsx"]);
        let run = parsed(&["decrypt", "-r", "docs", "more"]).unwrap();
        assert!(run.command == Command::Decrypt && run.options.recursive);
        assert_eq!(run.files, ["docs", "more"]);
        assert!(parsed(&["encrypt", "--recursive", "docs"]).unwrap().options.recursive);
        assert!(parsed(&["encrypt", "-n", "a"]).unwrap().options.hide_names);
        assert!(parsed(&["encrypt", "-r", "--hide-names", "docs"]).unwrap().options.hide_names);
        let hide = Options { hide_names: true, ..Options::default() };
        assert!(check(Command::Encrypt, &hide).is_ok());
        assert!(matches!(check(Command::Decrypt, &hide), Err(Error::Usage(_))));
        assert!(matches!(check(Command::View, &hide), Err(Error::Usage(_))));
        let recursive = Options { recursive: true, ..Options::default() };
        assert!(check(Command::Encrypt, &recursive).is_ok() && check(Command::Decrypt, &recursive).is_ok());
        assert!(matches!(check(Command::Update, &recursive), Err(Error::Usage(_))));
    }

    #[test]
    fn takes_update_on_its_own() {
        assert!(parsed(&["update"]).unwrap().command == Command::Update);
        assert!(usage_error(parsed(&["update", "report.pdf"])).contains("update doesn't take a file"));
        let yes = Options { yes: true, ..Options::default() };
        assert!(matches!(check(Command::Update, &yes), Err(Error::Usage(_))));
        assert!(check(Command::Update, &Options::default()).is_ok());
    }

    #[test]
    fn rejects_bad_command_lines() {
        assert!(usage_error(parsed(&["encrypt", "--key-file"])).contains("needs a path"));
        assert!(usage_error(parsed(&["encrypt", "--key-file="])).contains("needs a path"));
        assert!(usage_error(parsed(&["encrypt", "--yes=no", "f"])).contains("doesn't take a value"));
        assert!(usage_error(parsed(&["encrypt", "--force", "f"])).contains("unknown option '--force'"));
        assert!(usage_error(parsed(&["decrypt", "a.enc", "b.enc", "-o", "x"])).contains("--output names one"));
        assert!(usage_error(parsed(&["decrypt", "-r", "docs", "-o", "x"])).contains("--output names one"));
        assert!(usage_error(parsed(&["encrypt", "--recursive=yes", "docs"])).contains("doesn't take a value"));

        let both = Options { key_file: Some("a".into()), new_key: Some("b".into()), ..Options::default() };
        assert!(matches!(check(Command::Encrypt, &both), Err(Error::Usage(_))));
        let keep = Options { keep: true, ..Options::default() };
        assert!(matches!(check(Command::Decrypt, &keep), Err(Error::Usage(_))));
        let output = Options { output: Some("o".into()), ..Options::default() };
        assert!(matches!(check(Command::Encrypt, &output), Err(Error::Usage(_))));
        assert!(check(Command::Decrypt, &output).is_ok());
    }
}
