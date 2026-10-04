# encryptor

An interactive command-line tool for encrypting and decrypting files with
**AES-256-GCM**, written in Rust.

```
encrypt report.pdf        # → report.pdf.enc, original securely deleted
decrypt report.pdf.enc    # → report.pdf
```

Install it with npm on Linux or macOS:

```
npm install -g @neddyp/encryptor
```

See [Install](#install) for details, including permission errors.

## Features

- **AES-256-GCM authenticated encryption.** Any change to an encrypted file,
  even a single bit, is detected and decryption refuses to proceed.
- **Random or your own keys.** Generate a 256-bit key from the operating
  system's secure random generator, or supply one as 64 hex characters or a
  32-byte key file.
- **Generated keys are never shown unless you ask.** Save the key as a
  binary file readable only by you, print it once, or both.
- **Printed keys leave no trace.** A printed key appears on the terminal's
  alternate screen, which keeps no scrollback, and is erased when you press
  Enter. It is written straight to the terminal, never to standard output, so
  redirecting the output to a file can't capture it.
- **Warned before printing into a recording.** Before printing a key, the
  tool looks for anything that would capture it, such as `script`,
  `asciinema`, a terminal sharing tool, tmux `pipe-pane` or a tracer. If it
  finds one, it names it, with its PID and the file it writes to, warns that
  printing would compromise the encryption, and asks whether to print anyway.
- **Verified before anything is deleted.** After encrypting, the new file is
  read back from disk and decrypted, and its SHA-256 is compared with the
  original. The original is deleted only if they match.
- **Original overwritten, then deleted.** The plaintext file is overwritten
  with zeros and flushed to disk, renamed to random characters so its name
  doesn't linger either, then removed. It is opened once and handled through
  that one handle, so swapping it for a symlink part way through can't
  redirect the overwrite to another file.
- **Nothing left in memory.** Keys, plaintext and typed input are kept in RAM
  (never swapped out) and zeroed as soon as they're no longer needed. Core
  dumps are disabled, and on Linux other programs running as you can't read
  the tool's memory.
- **Nothing left on disk.** Unused key files, partial output and output that
  fails verification are overwritten with zeros before they're deleted. The
  tool writes no logs.
- **Keys scrubbed from shell history.** Whenever a key is used, any copy of it
  in your bash, zsh or fish history files is overwritten with asterisks, in
  case it was ever typed or pasted into a command.
- **Hidden key entry.** Keys typed at the prompt are not echoed. When
  encrypting, a typed key must be entered twice so a typo can't lock the file
  for good.
- **Safe to interrupt.** Ctrl-C at any point stops cleanly: keys are wiped,
  unused key files and partial output are shredded, and the original is left
  untouched unless encryption had already been verified.
- **Metadata comes back too.** Permissions, timestamps, owner and extended
  attributes (which hold ACLs on Linux, and Finder tags and download
  quarantine on macOS) are stored inside the encryption, so they don't leak,
  and put back on the decrypted file. Any file type works: the tool only sees
  bytes.
- **Errors that say how to fix them.** A missing file suggests the one you
  probably meant, a full or read-only disk or a FAT32 size limit is named as
  such, a file that isn't encrypted is identified (a zip, a PDF, or a file
  from OpenSSL, GPG or age), and a mistyped key is described without being
  shown. Suggested commands use your own file names, ready to paste.
- **Crash-safe writes.** Output goes to a temporary file that is renamed into
  place, so a half-written file never appears under the final name.

## Install

### With npm

Works on Linux and macOS, on both x64 and arm64 (Apple Silicon), with
Node.js 16 or newer. The package ships a prebuilt binary for each platform,
so you don't need Rust.

```
npm install -g @neddyp/encryptor
```

That puts `encrypt`, `decrypt` and `aes256` on your `PATH`. Check it worked:

```
encrypt --help
```

**Permission denied (`EACCES`)?** On Linux with Node from your distribution's
packages, global installs go into `/usr/local`, which needs root. Either
install with sudo:

```
sudo npm install -g @neddyp/encryptor
```

or have npm install global packages into your home directory instead, once,
and then install without sudo. `~/.local/bin` must be on your `PATH`; most
distributions add it automatically if it exists when you log in.

```
npm config set prefix ~/.local
npm install -g @neddyp/encryptor
```

**Updating** to the latest release (add `sudo` if you installed with it):

```
npm install -g @neddyp/encryptor@latest
```

**Uninstalling:**

```
npm uninstall -g @neddyp/encryptor
```

Windows isn't supported; npm refuses to install there with `EBADPLATFORM`.

### From source

You need Rust 1.89 or newer (`rustc --version`). On Ubuntu 26.04 and later
the packaged version is new enough (`sudo apt install rustc cargo`);
otherwise install it from [rustup.rs](https://rustup.rs).

```
git clone https://github.com/neddyP/encryptor.git
cd encryptor
cargo build --release
```

Then put the repo's `bin/` folder on your `PATH` so `encrypt`, `decrypt` and
`aes256` work from any directory. Add this to `~/.bashrc`, adjusting the path to where
you cloned the repo:

```bash
export PATH="$HOME/encryptor/bin:$PATH"
```

Reload with `source ~/.bashrc` and check with `type encrypt`.

`bin/encrypt`, `bin/decrypt` and `bin/aes256` are symlinks to
`target/release/aes256`, so rebuilding updates them automatically. After a
`cargo clean`, run `cargo build --release` again to bring them back.

If you also have the npm package installed, whichever `encrypt` comes first
on your `PATH` is the one that runs. `type -a encrypt` lists them all.

## Usage

```
encrypt [FILE]    encrypt FILE to FILE.enc, then delete FILE
decrypt [FILE]    decrypt FILE.enc back to FILE
aes256            choose encrypt or decrypt interactively
```

If you leave out `FILE`, you're asked for it. Typed paths may be quoted or
start with `~/`, so you can drag a file into the terminal. `encrypt --help`
prints the usage.

`encrypt` takes one file at a time. To encrypt a folder or several files, zip
them into a single file first. Given a folder or more than one file, `encrypt`
prints the commands to do this, using your own names:

```
$ encrypt photos
error: photos is a folder.
encrypt can't encrypt folders or multiple files, only one file at a time.
Zip them into a single file, then encrypt that:

  Zip the folder:    zip -r photos.zip photos
  Encrypt the zip:   encrypt photos.zip

encrypt deletes the zip once it's encrypted, but not the originals: delete
them yourself once you've checked the encrypted file.
```

### Encrypting

```
$ encrypt report.pdf
Generate a random 256-bit key? [y/n]: y
Key generated (not displayed).
Save symmetric encryption key as a file in your current directory? [y/n]: y
Key saved as: report.pdf.key
Keep this file safe: anyone who has it can decrypt the file, and
without the key the file cannot be decrypted.
Print the key? [y/n]: n
Encrypt using AES-256-GCM? [y/n]: y

----------------------------------------------------------------
  ENCRYPTION SUCCESSFUL
----------------------------------------------------------------
  Cipher         AES-256-GCM (authenticated encryption)
  Key            256-bit, generated by the OS CSPRNG
  Key storage    saved to /home/you/Documents/report.pdf.key (owner read/write only)
  Nonce          96-bit, random
  Auth tag       128-bit
  Input          report.pdf  1258291 bytes (1.2 MiB)
  Output         report.pdf.enc  1258401 bytes (1.2 MiB)
  Overhead       110 bytes (17 header + 77 metadata + 16 tag)
  Metadata       stored encrypted: permissions 644, owner 1000:1000, accessed, modified and created times
  Integrity      verified: re-read from disk, decrypted, SHA-256 matches original
  Original       overwritten with zeros, name scrambled, then deleted
  Key and data   kept in RAM (never swapped), wiped after use
  Time           15.75ms
----------------------------------------------------------------
```

The prompts go in this order:

1. **Generate a random key?** Answer `n` to enter your own key instead; the
   save and print questions are then skipped.
2. **Save the key as a file?** `y` saves it as a 32-byte binary file named
   `<file>.key` in the **current directory**, readable only by you (a number
   is added if the name is taken).
3. **Print the key?** `y` shows it once as 64 hex characters on the
   terminal's alternate screen; press Enter when you've copied it and it's
   erased. Printing needs an interactive terminal and is refused when there
   isn't one. If [something is recording the
   session](#when-the-session-is-being-recorded), you're told what and asked
   whether to print anyway. You can answer `y` to both questions to keep two
   copies.

   If you answer `n` to both, you're warned that the key would be lost (and
   the file with it) and asked `Print or save the key? [p/s]` until you
   choose one.
4. **Encrypt?** `n` cancels. A key file saved earlier is then removed, since
   it never encrypted anything.

If `FILE.enc` already exists, the tool refuses to run rather than overwrite it.

### When the session is being recorded

Asked to print a key, the tool first checks whether anything would capture
it. If so, it says exactly what, and asks before printing:

```
Print the key? [y/n]: y

WARNING: something is recording or sharing this terminal session:
  - script (PID 4242): records the terminal session
      writing to /home/you/typescript
Printing the key would save it to script compromising your encryption, do you still wish to print your decryption key? [y/n]: n
Key not printed.
```

`y` prints it anyway, into the recording, and the final report says the key
was captured and by what, rather than that it was erased. `n` leaves it
unprinted, and if the key hasn't been saved either, you're then asked to
print or save it.

It looks for:

- **Recorders and logging shells** the session runs inside: `script`,
  `asciinema`, `ttyrec`, `termrec`, tlog, Terminalizer, VHS, `t-rec`,
  `rootsh` and `sudosh`. `script` writing to `/dev/null`, a common way to get
  a terminal without recording anything, doesn't count.
- **Terminal sharing:** tmate, tty-share, upterm, sshx, ttyd and GoTTY.
- **GNU screen**, which keeps what the key is shown on in its scrollback.
- **tmux** `pipe-pane` on the current pane (which tmux-logging uses), and
  recorders around any tmux client attached to the session. tmux itself keeps
  no copy of a printed key.
- **Debuggers and tracers** such as `strace` and `gdb` attached to the tool
  (Linux only).

On Linux the warning also lists the files each one is writing to. Some
recorders can't be seen from inside the session; see
[Security notes](#security-notes).

### Decrypting

```
$ decrypt report.pdf.enc
Enter key (64 hex characters, or path to a key file):
Decrypt using AES-256-GCM? [y/n]: y

----------------------------------------------------------------
  DECRYPTION SUCCESSFUL
----------------------------------------------------------------
  Cipher         AES-256-GCM (authenticated encryption)
  Key            256-bit
  Auth tag       128-bit, valid: file is authentic and uncorrupted
  Input          report.pdf.enc  1258401 bytes (1.2 MiB) (kept)
  Output         report.pdf  1258291 bytes (1.2 MiB)
  Integrity      verified: re-read from disk, SHA-256 matches decrypted data
  Metadata       restored permissions 644, accessed and modified times; not restored: created time (this system can't set it)
  Key and data   kept in RAM (never swapped), wiped after use
  Shell history  key not found in shell history
  Time           10.90ms
----------------------------------------------------------------
```

At the key prompt, either type or paste the hex key, or give the path to the
key file (for example `report.pdf.key`). Neither is echoed. You get three
attempts.

The `.enc` suffix is removed to name the output. Files without it get `.dec`
added instead. If the output file already exists, you're asked before it is
overwritten. The encrypted file is kept.

The decrypted file gets the original's metadata back, and the report lists
anything that couldn't be restored:

- **Permissions, and access and modification times**, to the nanosecond.
- **Extended attributes**, including POSIX ACLs on Linux, and Finder tags and
  the download quarantine flag on macOS.
- **Creation time** on macOS. Linux has no way to set it.
- **Owner and group**, as far as your account allows. Only root can give a
  file to another user, and you can only give a file to one of your own
  groups.
- **Setuid, setgid and file capabilities** only along with the original
  owner, as `cp -p` does, so nobody can be handed a program that runs with
  someone else's privileges.

On macOS, ACLs and file flags (such as hidden or locked) aren't kept.

Files encrypted by versions before 2.0 hold no metadata. They still decrypt,
and the report says none was stored.

A wrong key and a damaged or tampered file produce the same error, because
GCM can't tell them apart. Nothing is written in either case, and the error
says what to check, including when the key file is named for a different
file:

```
error: authentication failed: wrong key, or the file is corrupted or has been tampered with.
Nothing was written.
- You used the key file photo.jpg.key, but the key for report.pdf.enc is usually report.pdf.key.
- Check it's this file's key: every generated key is different, even for the same file encrypted twice.
- If the key is right, report.pdf.enc was changed or damaged after it was encrypted, for example by an incomplete copy or download. Try another copy of it.
```

### Scripting

When standard input isn't a terminal, answers and keys are read line by line
from it. The key is then read as plain text, so use this only where that's
acceptable. Prefer passing the path to a key file, as here:

```
printf 'report.pdf.key\ny\n' | decrypt report.pdf.enc
```

Typing a hex key into a command like this puts it in your shell's history.
The tool overwrites it in your history files the next time that key is used,
but it can't reach the copy the running shell holds in memory, which is saved
when the shell exits. If you've done this, run `history -c` in that shell.
Printing a key isn't possible without an interactive terminal.

## File format

| Offset | Size | Contents                                  |
| ------ | ---- | ----------------------------------------- |
| 0      | 4    | Magic bytes `AGCM`                        |
| 4      | 1    | Format version (`2`)                      |
| 5      | 12   | Nonce, random per file                    |
| 17     | n    | Ciphertext (same length as the plaintext) |
| 17 + n | 16   | GCM authentication tag                    |

The 17-byte header is passed to GCM as associated data, so it is
authenticated along with the ciphertext.

The plaintext starts with the original file's metadata, so it is encrypted
and authenticated along with the contents:

| Size | Contents                                  |
| ---- | ----------------------------------------- |
| 4    | Length `m` of the metadata records        |
| m    | Metadata records                          |
| rest | The file's contents                       |

Each record is a 1-byte tag, a 4-byte length and the value. Numbers are
little-endian. Records with unknown tags are skipped.

| Tag | Value                                                         |
| --- | ------------------------------------------------------------- |
| 1   | Permission bits, including setuid, setgid and sticky (u32)    |
| 2   | Owner and group IDs (u32, u32)                                |
| 3   | Access time: seconds since 1970 (i64), then nanoseconds (u32) |
| 4   | Modification time, as for tag 3                               |
| 5   | Creation time, as for tag 3                                   |
| 6   | Extended attribute: name, a zero byte, then the value         |

Version 1 files, made by versions of encryptor before 2.0, have no metadata:
the plaintext is just the contents. 2.0 and later read both, but earlier
versions can't read version 2.

The format is plain AES-256-GCM and can be decrypted by any standard
implementation. For example, with Python's `cryptography` package:

```python
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

blob = open("report.pdf.enc", "rb").read()
key = open("report.pdf.key", "rb").read()
plaintext = AESGCM(key).decrypt(blob[5:17], blob[17:], blob[:17])
if blob[4] >= 2:  # skip the metadata
    (length,) = struct.unpack_from("<I", plaintext)
    plaintext = plaintext[4 + length:]
```

## Security notes

- **Lose the key, lose the file.** There's no recovery or backdoor. Keep key
  files somewhere other than next to the encrypted file.
- **Overwriting isn't guaranteed to erase.** SSD wear levelling, copy-on-write
  filesystems (btrfs, ZFS) and backups can keep old copies of the original,
  and of history lines and files the tool overwrites. Full-disk encryption is
  the reliable protection for those.
- **Large files can reach swap.** Keys are always locked in RAM, but the
  system's memory-lock limit (often 8 MiB) caps how much plaintext can be.
  The report says which applied. Encrypted swap, or no swap, covers the rest.
- **Not every recorder can be detected.** Terminal emulator session logs
  (such as iTerm2's automatic logging), recorders on the machine you
  connected from over SSH, sudo I/O logs and kernel keystroke auditing
  (`pam_tty_audit`) can't be seen from inside the session, and would capture
  a printed key. Save the key instead of printing it when a session might be
  recorded.
- **Whole files are processed in memory.** You need free RAM at least the size
  of the file. AES-GCM limits a single file to 64 GiB.
- **Keys are raw 256-bit values, not passwords.** There's no password-based
  key derivation, so use generated keys rather than typing in something
  memorable.
- **Files the tool creates are owner-only** (mode `600`): encrypted files,
  key files, and decrypted files until they have been verified. A decrypted
  file then gets the original's permissions back, which may let others read
  it if the original did. Symlinks are rejected as input, so the tool never
  overwrites the file a link points to.
- **Metadata is encrypted, but the size isn't.** An encrypted file is the
  original's size plus 33 bytes plus the metadata, and its name is the
  original's with `.enc` added.
- `.gitignore` excludes `*.key`, so key files saved inside the repo can't be
  committed by accident.

## Development

```
cargo test --release
```

The tests cover round trips at several sizes, wrong-key rejection, detection
of a change to any single byte, truncation, nonce uniqueness, key parsing,
overwriting and deleting files (including when a file is swapped for a
symlink part way through), history redaction, escaping of untrusted file
names, recognising recorders and the files they write to, storing and restoring
metadata (including reading files from earlier versions), and the advice in
error messages.

The code is in `src/`: `main.rs` has the commands and crypto, `protect.rs`
the process hardening and memory locking, `term.rs` the terminal input and
output, `recording.rs` the search for anything recording the session,
`meta.rs` the stored metadata, `explain.rs` the error messages, and `wipe.rs`
secure deletion and history redaction. It uses the
RustCrypto [`aes-gcm`](https://crates.io/crates/aes-gcm) and
[`sha2`](https://crates.io/crates/sha2) crates,
[`zeroize`](https://crates.io/crates/zeroize) for wiping secrets,
[`getrandom`](https://crates.io/crates/getrandom) for randomness and
[`libc`](https://crates.io/crates/libc) for the system calls.

## Releasing

Releases are built and published by `.github/workflows/release.yml`, using
npm trusted publishing so no npm token is stored in the repo. Each release
tests and builds static Linux binaries (x64 and arm64) and macOS binaries
(x64 and arm64) and packs them into the npm package.

- **Monthly, automatically.** On the 1st of each month, if anything that goes
  into the package (`src/`, `Cargo.toml`, `Cargo.lock`, `npm/`, `README.md`,
  `LICENSE`) changed since the last `v*` tag, the workflow bumps the patch version,
  commits and tags it as `github-actions[bot]`, and publishes. If you've
  already raised the version by hand, it releases that version instead. If
  nothing changed, it stops before building.
- **Straight away, with a tag.** Set the new version in both `Cargo.toml` and
  `npm/package.json`, commit, then:

  ```
  git tag v0.2.0
  git push origin master v0.2.0
  ```

  The workflow stops if the tag and the two version numbers don't all match.
- **Dry run.** Running the workflow by hand from the Actions tab does
  everything except the publish.

Every run keeps the packed tarball as the `npm-package` artifact. The
decision logic is in `.github/release-plan.sh`.

The npm package lives in `npm/`. `bin/*.js` are small Node launchers that run
the right binary from `vendor/<platform>/aes256`, which `npm/stage.sh` fills
in from the build artifacts.

## License

MIT. See the `LICENSE` file.
