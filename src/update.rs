//! `encryptor update`: replaces this copy with the latest release, the way it
//! was installed. A copy installed with npm is updated with npm, into the same
//! prefix. One in /usr/local/bin, where install.sh puts it, is updated by
//! running that script, built into the program so it's the one this release
//! shipped with rather than whatever is online. The program goes online only
//! when asked to update: it never checks for a new version by itself.

use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::{explain, protect, timestamps};

/// install.sh as of this release.
const INSTALL_SCRIPT: &str = include_str!("../install.sh");
/// Where install.sh installs the binary.
const INSTALL_DIR: &str = "/usr/local/bin";
const PACKAGE: &str = "@neddyp/encryptor@latest";

/// How this copy was installed, as told by where its binary is.
#[derive(Debug, PartialEq)]
enum Install {
    /// With install.sh.
    Script,
    /// With `npm install -g`, into this prefix.
    Npm(PathBuf),
    /// Some other way, such as built from source.
    Other,
}

pub fn command() -> Result<()> {
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| Error::Message(format!("couldn't tell where this copy of encryptor is: {e}")))?;
    let old = env!("CARGO_PKG_VERSION");
    let (mut update, how) = match install_of(&exe) {
        Install::Script => {
            let mut sh = Command::new("sh");
            sh.arg("-c").arg(INSTALL_SCRIPT);
            (sh, "install.sh")
        }
        Install::Npm(prefix) => (npm(&prefix), "npm"),
        Install::Other => return Err(Error::Message(explain::cant_update(&exe))),
    };
    eprintln!("Updating encryptor {old} with {how}...");
    let status = update
        .status()
        .map_err(|e| Error::Message(format!("couldn't run {how} to update encryptor: {e}")))?;
    protect::check()?;
    if !status.success() {
        return Err(Error::Message(format!(
            "the update didn't finish, as {how} said above. encryptor {old} is still installed."
        )));
    }
    match installed_version(&exe) {
        Some(new) if new == old => println!("encryptor {old} is already the latest version."),
        Some(new) => println!("Updated encryptor from {old} to {new}."),
        None => println!("Updated encryptor."),
    }
    Ok(())
}

fn install_of(exe: &Path) -> Install {
    if exe.parent() == Some(Path::new(INSTALL_DIR)) {
        return Install::Script;
    }
    // npm installs global packages in <prefix>/lib/node_modules, and the
    // package keeps the binary in vendor/<platform>.
    let dirs: Vec<&Path> = exe.ancestors().collect();
    let name = |i: usize| dirs.get(i).and_then(|dir| dir.file_name()).and_then(|name| name.to_str());
    let layout = [(2, "vendor"), (3, "encryptor"), (4, "@neddyp"), (5, "node_modules"), (6, "lib")];
    match dirs.get(7) {
        Some(prefix) if layout.iter().all(|&(i, expected)| name(i) == Some(expected)) => {
            Install::Npm(prefix.to_path_buf())
        }
        _ => Install::Other,
    }
}

/// `npm install -g` of the latest release into `prefix`, with sudo if the
/// package's folder isn't writable, as after `sudo npm install -g`. It uses
/// the npm beside the Node.js that ran the package's launcher, with that
/// Node.js first on the PATH for npm's own `#!/usr/bin/env node`.
fn npm(prefix: &Path) -> Command {
    let node_dir = std::env::var_os(timestamps::NODE_VAR)
        .map(PathBuf::from)
        .and_then(|node| node.parent().map(Path::to_path_buf));
    let npm = node_dir.as_ref().map(|dir| dir.join("npm")).filter(|npm| npm.exists());
    let npm = npm.map_or_else(|| OsString::from("npm"), PathBuf::into_os_string);
    let paths = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(node_dir.into_iter().chain(std::env::split_paths(&paths))).unwrap_or(paths);

    let mut command = if writable(&prefix.join("lib/node_modules/@neddyp")) {
        Command::new(npm)
    } else {
        // sudo can reset the PATH, and npm needs Node.js on it.
        let mut setting = OsString::from("PATH=");
        setting.push(&path);
        let mut sudo = Command::new("sudo");
        sudo.arg("env").arg(setting).arg(npm);
        sudo
    };
    command.args(["install", "--global", "--prefix"]).arg(prefix).arg(PACKAGE).env("PATH", path);
    command
}

fn writable(dir: &Path) -> bool {
    let Ok(dir) = CString::new(dir.as_os_str().as_bytes()) else { return false };
    // SAFETY: a valid C path.
    unsafe { libc::access(dir.as_ptr(), libc::W_OK) == 0 }
}

/// The version of the binary at `exe` now, from its --version.
fn installed_version(exe: &Path) -> Option<String> {
    let output = Command::new(exe).arg("--version").stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.strip_prefix("encryptor ")?.split(',').next()?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_how_it_was_installed_from_where_it_is() {
        let install = |path: &str| install_of(Path::new(path));
        assert_eq!(install("/usr/local/bin/encryptor"), Install::Script);
        assert_eq!(
            install("/usr/local/lib/node_modules/@neddyp/encryptor/vendor/linux-x64/encryptor"),
            Install::Npm("/usr/local".into())
        );
        assert_eq!(
            install("/home/me/.local/lib/node_modules/@neddyp/encryptor/vendor/darwin-arm64/encryptor"),
            Install::Npm("/home/me/.local".into())
        );
        // A project's own node_modules, not a global install.
        assert_eq!(install("/home/me/app/node_modules/@neddyp/encryptor/vendor/linux-x64/encryptor"), Install::Other);
        assert_eq!(install("/home/me/encryptor/target/release/encryptor"), Install::Other);
        assert_eq!(install("/usr/local/bin/other/encryptor"), Install::Other);
    }

    #[test]
    fn carries_the_install_script() {
        assert!(INSTALL_SCRIPT.starts_with("#!/bin/sh"));
        assert!(INSTALL_SCRIPT.contains(&format!("dir={INSTALL_DIR}\n")));
    }
}
