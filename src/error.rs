//! Why the program stopped before finishing, and the exit status that says so.

use std::fmt;

/// An error, carrying a message already written for the user except where
/// the program handles the case differently. The kind decides the exit
/// status, so scripts can tell what happened.
#[derive(Debug)]
pub enum Error {
    /// The user asked to stop, with Ctrl-C or similar. Keys, plaintext and
    /// partial files have been cleaned up on the way out.
    Interrupted,
    /// A whole version 1 or 2 file failed to authenticate: the key is wrong or
    /// the file damaged. The caller explains it with what it knows.
    AuthFailed,
    /// A bad command line: unknown or conflicting options, too many files, or
    /// a question a script has to answer with an option.
    Usage(String),
    /// The key doesn't fit the file, or the encrypted file is damaged.
    KeyOrData(String),
    /// A file is missing or the wrong kind, or can't be read or written.
    File(String),
    /// Anything else.
    Message(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Interrupted => 130,
            Self::Usage(_) => 2,
            Self::AuthFailed | Self::KeyOrData(_) => 3,
            Self::File(_) => 4,
            Self::Message(_) => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted => f.write_str("interrupted; nothing was left behind"),
            Self::AuthFailed => f.write_str(crate::explain::AUTH_FAILED),
            Self::Usage(m) | Self::KeyOrData(m) | Self::File(m) | Self::Message(m) => f.write_str(m),
        }
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::Message(message.into())
    }
}
