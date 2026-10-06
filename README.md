# encryptor

An interactive command-line tool for encrypting and decrypting files with
**AES-256-GCM**, written in Rust.

```
encrypt report.pdf        # → report.pdf.enc, original securely deleted
decrypt report.pdf.enc    # → report.pdf
```

Install it on Linux or macOS with:

```
curl -fsSL https://raw.githubusercontent.com/neddyP/encryptor/master/install.sh | sh
```

That downloads the one prebuilt binary for your system, about 1 MB, into
`/usr/local/bin`. It needs nothing else: no Node.js, no Rust. Or install it
with npm:

```
npm install -g @neddyp/encryptor
```

Either way, `encryptor update` updates it. See [Install](#install) for details.

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
  flushed to disk and read back from the disk itself, not from the copy the
  system keeps in memory, then decrypted, and its SHA-256 is compared with
  the original. The original is deleted only if they match. Decrypted files
  are checked the same way.
- **Original overwritten, then deleted.** The plaintext file is overwritten
  with zeros and flushed to disk, renamed to random characters so its name
  doesn't linger either, then removed. It is opened once and handled through
  that one handle, so swapping it for a symlink part way through can't
  redirect the overwrite to another file. A read-only original you own is
  allowed writing just long enough to open it, with its permissions put back
  straight away. A file that can't be overwritten, or that other names (hard
  links) also lead to, is refused before any key is made.
- **Nothing left in memory.** Keys, plaintext and typed input are kept in RAM
  (never swapped out) and zeroed as soon as they're no longer needed, and
  every other block of memory the tool frees, holding file names, answers or
  the report, is overwritten with zeros too. Core dumps are disabled, and on
  Linux other programs running as you can't read the tool's memory.
- **Nothing left on disk.** Unused key files, partial output, output that
  fails verification, and a file that decrypting replaces are overwritten
  with zeros before they're deleted, and temporary files have random names.
  The tool writes no logs.
- **No trace on the desktop.** On Linux, the original's thumbnails (small
  pictures of its contents, made when a file manager or file picker showed
  it) are shredded, and its entry in the desktop's list of recently used
  files is removed.
- **No trace in shell history.** Every run removes the entries in your bash,
  zsh and fish history files that ran the tool, including the history macOS's
  Terminal keeps for each window (`~/.bash_sessions`, `~/.zsh_sessions`), and
  every key it uses is removed with the entries holding it, in case it was
  ever typed or pasted into a command. The files are rewritten in place, and
  the bytes left over are zeroed before they're cut short.
- **Its own files don't show when it ran.** Running a program reads its
  files, which updates their last-read times. At the end of every run, its
  binary's last-read time is set back to when it was installed, and with the
  npm package, so are the package's files, the command's link and the Node.js
  that started it. The folders a run writes in get their modified times set
  back to what they were before it started.
- **Offline unless you update.** encryptor never connects to the network on
  its own. `encryptor update` is the only thing that does, and only when you
  run it.
- **Saved summaries don't name the file.** The report on screen is complete,
  but a summary you choose to save is called `encryption-summary.txt` (or
  `decryption-summary.txt`), and every file name and path in it is replaced
  with `…`. It says what was done, not to which file.
- **Runs on a screen of its own, wiped when you're done.** At a terminal,
  whatever the command, encryptor takes over the window, with its name in
  large letters at the top. When you press Enter at the end, everything it
  showed is wiped and your window comes back as it was, with all its earlier
  history. None of it reaches the window's scrollback.
- **Warned about disks that keep old copies.** On a copy-on-write filesystem
  (APFS, btrfs, ZFS and the like) overwriting can't reach a file's old
  contents, so you're told and asked before encrypting.
- **Hidden key entry.** Keys typed at the prompt are not echoed. When
  encrypting, a typed key must be entered twice so a typo can't lock the file
  for good.
- **Safe to interrupt.** Ctrl-C at any point stops cleanly: keys are wiped,
  unused key files and partial output are shredded, and the original is left
  untouched unless encryption had already been verified. Shredding a large
  partial file shows its progress.
- **Files of any size, in a few megabytes of memory.** Files are encrypted
  in 64 KiB chunks, each authenticated on its own, so even files far larger
  than the computer's memory are handled with only one chunk in memory at a
  time, and plaintext never leaves locked RAM. Large files show their
  progress.
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

encryptor runs on Linux and macOS. Windows isn't supported.

### With install.sh

Works on Linux on x64, arm64, and 32-bit x86 and arm (ARMv6 or later, such
as any Raspberry Pi), and on macOS on Intel and Apple Silicon. It needs only
curl or wget:

```
curl -fsSL https://raw.githubusercontent.com/neddyP/encryptor/master/install.sh | sh
```

or `wget -qO- https://raw.githubusercontent.com/neddyP/encryptor/master/install.sh | sh`.
To read the script before running it, download it and run `sh install.sh`.

It downloads the binary for your system from the latest
[GitHub release](https://github.com/neddyP/encryptor/releases), over HTTPS
only with curl, and installs it as `/usr/local/bin/encryptor`, with `encrypt`
and `decrypt` linked to it. If you can't write to `/usr/local/bin` yourself,
as usual unless you're root, it uses sudo for that, which asks for your
password. On a system without sudo, it installs into `~/.local/bin` instead,
for you alone, and tells you how to add that folder to your `PATH` if it isn't
there yet. The binary is statically linked, so it runs on any distribution
and needs nothing else installed.

Check it worked:

```
encryptor --help
```

**Updating:** `encryptor update`, which updates the copy in the folder it's
in, or run the install command again.

**Uninstalling:**

```
cd /usr/local/bin && sudo rm encryptor encrypt decrypt
```

or, if it went into `~/.local/bin`, the same there without `sudo`.

### With npm

Works on Linux and macOS, on both x64 and arm64 (Apple Silicon), with
Node.js 16 or newer. The package ships a prebuilt binary for each platform,
so you don't need Rust.

```
npm install -g @neddyp/encryptor
```

That puts `encrypt`, `decrypt` and `encryptor` on your `PATH`. Check it
worked:

```
encryptor --help
```

`aes256`, the old name for `encryptor`, still works until 3.0, with a note
saying so.

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

**Updating** to the latest release runs npm for you, with sudo if you
installed with sudo:

```
encryptor update
```

or with npm directly (add `sudo` if you installed with it):

```
npm install -g @neddyp/encryptor@latest
```

**Uninstalling:**

```
npm uninstall -g @neddyp/encryptor
```

**Installed with the old install.sh?** It installed Node.js and the npm
package under `~/.local`, without sudo. That copy keeps working, and
`encryptor update` keeps updating it with npm. To switch to the binary in
`/usr/local/bin`, remove the npm copy first, so the two don't compete on your
`PATH`, then run the install command above:

```
npm uninstall -g --prefix ~/.local @neddyp/encryptor
```

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
`encryptor` work from any directory. Add this to `~/.bashrc`, adjusting the path to where
you cloned the repo:

```bash
export PATH="$HOME/encryptor/bin:$PATH"
```

Reload with `source ~/.bashrc` and check with `type encrypt`.

`bin/encrypt`, `bin/decrypt` and `bin/encryptor` (and `bin/aes256`, its old
name) are symlinks to `target/release/encryptor`, so rebuilding updates them
automatically. After a
`cargo clean`, run `cargo build --release` again to bring them back.

A copy built from source is updated by pulling the latest source and
building it again; `encryptor update` says so rather than replacing it. If
you also installed it another way, whichever `encrypt` comes first on your
`PATH` is the one that runs. `type -a encrypt` lists them all.

## Usage

```
encrypt FILE [OPTIONS]         encrypt FILE to FILE.enc, then delete FILE
decrypt FILE.enc [OPTIONS]     decrypt FILE.enc back to FILE
encryptor                      show the home screen, to encrypt or decrypt
encryptor update               update to the latest release
```

`encryptor update` updates it the way it was installed. For a copy install.sh
put in `/usr/local/bin` or `~/.local/bin`, it runs install.sh again for that
folder, the copy built into the program rather than one fetched at update
time. For the npm package, it runs
npm, into the same place, with sudo if that place belongs to root. It ends by
saying which version you went from and to, or that you already have the
latest. It's the only time encryptor goes online; it never checks for
updates by itself.

`encryptor encrypt FILE` and `encryptor decrypt FILE` do the same as
`encrypt` and `decrypt`. Each option answers one of the questions in
advance, so it isn't asked:

| Option                | What it does                                                        |
| --------------------- | ------------------------------------------------------------------- |
| `-k`, `--key-file KEY` | Use the key in `KEY`: 32 bytes, or 64 hex characters. It can be a pipe |
| `--new-key PATH`      | Encrypt with a new key, saved to `PATH`, or into `PATH` if it's a folder |
| `--keep`              | Encrypt, but keep the original instead of deleting it               |
| `-o`, `--output PATH` | Decrypt to `PATH` instead of next to the encrypted file            |
| `--overwrite`         | Decrypt over the output file if it already exists                   |
| `-y`, `--yes`         | Don't ask to confirm encrypting or decrypting                       |
| `-q`, `--quiet`       | Don't print the report                                              |
| `-h`, `--help`        | Show the usage                                                      |
| `-V`, `--version`     | Show the version and the file formats it reads                      |

At a terminal, every run, whatever the command or options, opens on a screen
of its own (the terminal's alternate screen, as used by `less` and `vim`),
with encryptor's name in large letters at the top. It ends with `Press Enter
to exit and wipe this screen`, after which everything it showed is gone and
your window is back as it was, earlier history and all. An error is shown
there before you press Enter. `q` on the home screen and Ctrl-C close it
straight away. In scripts, with no terminal, everything is printed as usual.

Run on its own, or with `--help`, `encryptor` shows a home screen: its name,
the version and this help. Press `e` to encrypt a file, `d` to decrypt one,
or `q` to quit; the arrow keys scroll if it doesn't all fit. Without a
terminal it asks "Encrypt or decrypt?" instead.

If you leave out `FILE`, you're asked for it. Typed paths may be quoted or
start with `~/`, so you can drag a file into the terminal.

Questions, warnings and errors go to standard error, and only the final
report to standard output, so `encrypt report.pdf > report.txt` still shows
every question and saves just the report. With its output redirected like
this, it runs in the window itself rather than on a screen of its own.

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
  File key       derived with HKDF-SHA256 from the key and a random 256-bit salt
  Chunks         20 of up to 64 KiB, each with its own 128-bit auth tag
  Input          report.pdf  1258291 bytes (1.2 MiB)
  Output         report.pdf.enc  1258725 bytes (1.2 MiB)
  Overhead       434 bytes (37 header + 77 metadata + 320 in tags)
  Metadata       stored encrypted: permissions 644, owner 1000:1000, accessed, modified and created times
  Integrity      verified: re-read from disk, decrypted, SHA-256 matches original
  Original       overwritten with zeros, name scrambled, then deleted
  Desktop traces removed 1 thumbnail and 1 recently used entry
  Key and data   kept in RAM (never swapped), wiped after use
  Shell history  removed 2 entries that ran this tool, from ~/.bash_history
  Time           15.75ms
----------------------------------------------------------------
Save this summary as encryption-summary.txt in the current folder? [y/n]: n

Press Enter to exit and wipe this screen:
```

The prompts go in this order:

0. **Encrypt anyway?** Asked only when the file is on a copy-on-write
   filesystem, such as APFS on a Mac or btrfs, which writes changes to a new
   place on the disk. Overwriting the original then can't reach its old
   contents, which stay on the disk until the space is reused, and in any
   snapshots. Full-disk encryption (FileVault or LUKS) keeps them unreadable
   without your password; on a Mac with FileVault off, the warning says so.
   It's only asked at a terminal: with `--yes`, or in a script, the warning
   is shown and encrypting goes ahead.
1. **Generate a random key?** Answer `n` to enter your own key instead; the
   save and print questions are then skipped.
2. **Save the key as a file?** `y` saves it as a 32-byte binary file named
   `<file>.key` in the **current directory**, readable only by you (a number
   is added if the name is taken).
3. **Print the key?** `y` clears the screen and shows the key once as 64
   hex characters; press Enter when you've written it down and it's erased,
   and the screen is drawn again with the file and key file so far. The key
   screen warns that selecting the key to copy it puts it on your clipboard,
   where clipboard history keeps a copy. Printing needs an interactive
   terminal and is refused when there isn't one. If [something is recording the
   session](#when-the-session-is-being-recorded), you're told what and asked
   whether to print anyway. You can answer `y` to both questions to keep two
   copies.

   If you answer `n` to both, you're warned that the key would be lost (and
   the file with it) and asked `Print or save the key? [p/s]` until you
   choose one.
4. **Encrypt?** `n` cancels. A key file saved earlier is then removed, since
   it never encrypted anything.
5. **Save this summary?** `y` saves the report as `encryption-summary.txt`
   in the current directory, readable only by you (a number is added if the
   name is taken), with every file name and path left out. It's only asked at a
   terminal, and not with `--yes` or `--quiet`, so scripts never wait for it.
6. **Press Enter to exit and wipe this screen.** Everything encryptor showed
   is erased and your window comes back as it was before you ran it. If
   something recorded the session, it's named first, since its copy can't be
   wiped. Ctrl-C exits too. This is the end of every run at a terminal,
   whatever the options.

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
Enter key (64 hex characters, or path to a key file from current directory):
Decrypt using AES-256-GCM? [y/n]: y

----------------------------------------------------------------
  DECRYPTION SUCCESSFUL
----------------------------------------------------------------
  Cipher         AES-256-GCM (authenticated encryption)
  Key            256-bit
  Auth tag       128-bit, valid: file is authentic and uncorrupted
  Input          report.pdf.enc  1258725 bytes (1.2 MiB) (kept)
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
attempts. As after encrypting, you're then offered to save the summary, as
`decryption-summary.txt` with names and paths left out, and Enter exits and
wipes the screen.

The `.enc` suffix is removed to name the output. Files without it get `.dec`
added instead. If the output file already exists, you're asked before it is
overwritten, and the old file is then overwritten with zeros, as it is often
plaintext from an earlier decryption. If other hard links lead to it, it is
left as they see it instead, and the report says so. The encrypted file is
kept.

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

In scripts, give options rather than answers, so nothing is asked:

```
encrypt report.pdf --new-key ~/keys/ --yes                 # new key saved as ~/keys/report.pdf.key
encrypt backup.tar --key-file ~/keys/backup.key --keep -y  # encrypt a copy, keep the original
decrypt report.pdf.enc --key-file ~/keys/report.pdf.key --yes
decrypt report.pdf.enc --key-file <(pass show keys/report) --yes   # key from a password manager
```

Keys are never given on the command line itself, since every user can see
command lines and the shell saves them in its history. `--key-file` takes a
32-byte key file, or 64 hex characters as `encrypt` prints them, and can be a
pipe, so a key from a password manager never touches the disk.

The exit status says what happened:

| Status | Meaning                                                  |
| ------ | -------------------------------------------------------- |
| 0      | Success                                                  |
| 2      | Bad options, or a question a script must answer with one |
| 3      | Wrong key, or the encrypted file is damaged              |
| 4      | A file problem: missing, no permission, disk full        |
| 1      | Anything else                                            |
| 130    | Interrupted                                              |

Answers piped into standard input still work, read line by line in the order
the questions are asked, but print a note, and stop working in 3.0. Which
questions get asked depends on things a script can't see, such as whether the
output already exists, so answers can land on the wrong question. Two
questions are therefore never answered from a pipe:

- **Replacing an existing file** needs `--overwrite`. Without it, a script
  stops with status 2 before giving the key.
- **Printing a key while something records the session** is refused when no
  one is at the keyboard. `yes | encrypt` can't agree to it.

Encrypting on a copy-on-write disk isn't asked about from a pipe either,
since it's asked on some disks and not others: the warning is shown, and
encrypting goes ahead as with `--yes`.

A hex key piped in or typed into a command ends up in your shell's history.
The tool removes it from your history files the next time that key is used,
but it can't reach the copy the running shell holds in memory, which is saved
when the shell exits. If you've done this, run `history -c` in that shell.

## File format

| Offset | Size | Contents                                  |
| ------ | ---- | ----------------------------------------- |
| 0      | 4    | Magic bytes `AGCM`                        |
| 4      | 1    | Format version (`3`)                      |
| 5      | 32   | Salt, random per file                     |
| 37     |      | Chunks, one after another                 |

The plaintext is split into chunks of 64 KiB, and only the last may be
shorter. Each is encrypted with AES-256-GCM and followed by its 16-byte tag,
so a full chunk takes 65,552 bytes on disk.

- **Key.** Each file has its own AES key, derived from your key and the salt
  with HKDF-SHA256 (info `encryptor v3 file key`). So no two files share a
  key, even when you reuse yours.
- **Nonces.** Chunk *n* (counting from 0) uses the 12-byte nonce made of *n*
  as an 11-byte big-endian number, then `1` for the last chunk or `0` for any
  other.
- **Associated data.** The 37-byte header is the associated data of every
  chunk, so it is authenticated too.

Changing any byte, reordering, dropping or adding chunks, or cutting the file
short makes decryption fail. If the first chunk decrypts but a later one
doesn't, the key is right and the file is damaged from that chunk on, and the
error says where.

The plaintext, all the chunks in order, starts with the original file's
metadata, so it is encrypted and authenticated along with the contents:

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

The format uses only standard primitives, so any AES-GCM and HKDF
implementation can decrypt it. For example, with Python's `cryptography`
package:

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 64 * 1024 + 16  # 64 KiB of ciphertext, then its 16-byte tag

key = open("report.pdf.key", "rb").read()
with open("report.pdf.enc", "rb") as f:
    header = f.read(37)
    body = f.read()  # for a large file, decrypt as you read instead
aead = AESGCM(HKDF(hashes.SHA256(), 32, header[5:37], b"encryptor v3 file key").derive(key))
chunks = [body[i:i + CHUNK] for i in range(0, len(body), CHUNK)]
plaintext = b"".join(
    aead.decrypt(bytes(3) + n.to_bytes(8, "big") + bytes([n == len(chunks) - 1]), chunk, header)
    for n, chunk in enumerate(chunks)
)
length = int.from_bytes(plaintext[:4], "little")  # skip the metadata
contents = plaintext[4 + length:]
```

### Earlier formats

This version still decrypts files from earlier versions, which encrypted the
whole file in one piece, so decrypting them needs free memory the size of the
file. Earlier versions can't read version 3 files; they say so, and how to
update.

| Version | Made by     | Layout                                                    |
| ------- | ----------- | --------------------------------------------------------- |
| 2       | 2.0         | `AGCM`, `2`, 12-byte random nonce, ciphertext, 16-byte tag |
| 1       | before 2.0  | The same, with version `1` and no metadata                 |

In both, the 17-byte header is the associated data. Version 2's plaintext
starts with the metadata, as above; version 1's is just the contents.

## Security notes

- **Lose the key, lose the file.** There's no recovery or backdoor. Keep key
  files somewhere other than next to the encrypted file.
- **Overwriting isn't guaranteed to erase.** SSD wear levelling, copy-on-write
  filesystems (APFS, btrfs, ZFS), snapshots and backups can keep old copies
  of the original, and of history files and thumbnails the tool overwrites.
  Full-disk encryption is the reliable protection for those.
- **Some traces are out of the tool's reach.** It removes what it can find,
  but a run can still be told from:
  - **The command that ran it, in the shell you ran it from.** Shells keep
    their own session's history in memory and save it when they exit, after
    the tool has finished, so it's only removed by a later run. To keep it
    out, start the command with a space: bash does that with
    `HISTCONTROL=ignorespace` (or `ignoreboth`, Ubuntu's default), zsh with
    `setopt HIST_IGNORE_SPACE`, and fish always. Other shells left open can
    also write back entries they read when they started.
  - **Timestamps.** The `.enc` and `.key` files show when they were
    written. Their folders' modified times are set back, which updates the
    folders' change times instead. The tool's own files have their last-read times set
    back to when they were installed, but setting them updates their change
    times (`ctime`, shown by `stat`), which no program can set, so those show
    the last run instead. Only files actually read are set back, so on disks
    that don't record reads (mounted with `noatime`) nothing changes. A
    Node.js the tool can't change, such as one owned by root, keeps its
    last-read time.
  - **Copies other programs made.** Editor backups, downloads, email
    attachments, cloud sync and backups, desktop search indexes (GNOME's
    LocalSearch, KDE's Baloo), other programs' own lists of recent files,
    and on macOS, Quick Look's thumbnails and Spotlight.
  - **The command you typed.** It was in your window before encryptor
    started, so it's still there when the window comes back, with any file
    name in it.
  - **Terminals that keep the alternate screen.** iTerm2 can be set to save
    lines scrolled off it into the scrollback (encryptor reminds you of this
    in iTerm2), and GNU screen does so by default.
  - **Terminal records.** Session recorders, terminal emulator logs and GNU
    screen's scrollback keep their own copy of what was shown, as do sudo
    I/O logs and process accounting where a system administrator has turned
    them on.
- **Not every recorder can be detected.** Terminal emulator session logs
  (such as iTerm2's automatic logging), recorders on the machine you
  connected from over SSH, sudo I/O logs and kernel keystroke auditing
  (`pam_tty_audit`) can't be seen from inside the session, and would capture
  a printed key. Save the key instead of printing it when a session might be
  recorded.
- **Keys are raw 256-bit values, not passwords.** There's no password-based
  key derivation, so use generated keys rather than typing in something
  memorable.
- **Files the tool creates are owner-only** (mode `600`): encrypted files,
  key files, and decrypted files until they have been verified. A decrypted
  file then gets the original's permissions back, which may let others read
  it if the original did. Symlinks are rejected as input, so the tool never
  overwrites the file a link points to.
- **Metadata is encrypted, but the size isn't.** An encrypted file is the
  original's size plus 37 bytes, 16 bytes per 64 KiB, and the metadata, and
  its name is the original's with `.enc` added.
- `.gitignore` excludes `*.key`, so key files saved inside the repo can't be
  committed by accident.

## Development

```
cargo test --release
```

The tests cover round trips at sizes around the chunk boundaries, wrong-key
rejection, detection of a change to any chunk, of chunks reordered, added or
cut off, and of truncation, a known-answer test against a file made by
another implementation, decrypting the earlier formats, key parsing,
overwriting and deleting files (including when a file is swapped for a
symlink part way through, is read-only, or has other names), removing shell
history entries, thumbnails and recently used entries, escaping of untrusted file
names, recognising recorders and the files they write to, storing and restoring
metadata (including reading files from earlier versions), telling how a copy
was installed so `encryptor update` can update it, and the advice in error
messages. `tests/cli.rs` runs the program itself as a script would, with its
options, and checks its exit status and the files it leaves.

The code is in `src/`:

| File           | What it does                                                         |
| -------------- | -------------------------------------------------------------------- |
| `main.rs`      | Starting up, `--help` and `--version`                                |
| `cli.rs`       | The command line and its options                                     |
| `encrypt.rs`   | The encrypt command and its report                                   |
| `decrypt.rs`   | The decrypt command and its report                                   |
| `keys.rs`      | Generating, saving, printing and entering keys                       |
| `history.rs`   | Removing keys and runs of the tool from shell history                |
| `timestamps.rs` | Setting its own files' last-read times back to install time     |
| `desktop.rs`   | Removing the original's thumbnails and recently used entries         |
| `stream.rs`    | Chunked encryption, format version 3                                 |
| `legacy.rs`    | Decrypting format versions 1 and 2                                   |
| `meta.rs`      | The stored metadata                                                  |
| `files.rs`     | Checking input, reading back from disk, writing output safely        |
| `wipe.rs`      | Secure deletion, and rewriting files in place                        |
| `term.rs`      | Terminal input and output, prompts, progress                         |
| `recording.rs` | Finding anything recording the session                               |
| `explain.rs`   | Error messages and their fixes                                       |
| `error.rs`     | The error type                                                       |
| `protect.rs`   | Process hardening, memory locking and zeroing, interrupts            |
| `session.rs`   | The screen each run has to itself, and wiping it at the end          |
| `home.rs`      | The home screen                                                      |
| `report.rs`    | The report printed on success, and saving it                         |
| `update.rs`    | `encryptor update`, the way it was installed                         |

`install.sh`, at the top of the repo, is the installer, and is built into the
program for `encryptor update` to run.

It uses the RustCrypto
[`aes-gcm`](https://crates.io/crates/aes-gcm),
[`hkdf`](https://crates.io/crates/hkdf) and
[`sha2`](https://crates.io/crates/sha2) crates,
[`zeroize`](https://crates.io/crates/zeroize) for wiping secrets,
[`getrandom`](https://crates.io/crates/getrandom) for randomness,
[`md-5`](https://crates.io/crates/md-5) for finding thumbnails by name and
[`libc`](https://crates.io/crates/libc) for the system calls.

## Releasing

Releases are built and published by `.github/workflows/release.yml`, using
npm trusted publishing so no npm token is stored in the repo. Each release
tests and builds static Linux binaries (x64, arm64, and 32-bit x86 and arm)
and macOS binaries (x64 and arm64). The x64 and arm64 ones are packed into
the npm package, and all six are attached to the version's GitHub release as
`encryptor-<os>-<arch>`, where install.sh downloads them from. A release you
made by hand for the tag keeps its title and notes; otherwise one is made.

- **Monthly, automatically.** On the 1st of each month, if anything that goes
  into the package (`src/`, `Cargo.toml`, `Cargo.lock`, `npm/`, `README.md`,
  `LICENSE`, `install.sh`) changed since the last `v*` tag, the workflow bumps
  the patch version, commits and tags it as `github-actions[bot]`, and
  publishes. If you've already raised the version by hand, it releases that
  version instead. If nothing changed, it stops before building.
- **Straight away, with a tag.** Set the new version with
  `.github/set-version.sh`, which updates `Cargo.toml`, `Cargo.lock` and
  `npm/package.json`, commit, then:

  ```
  .github/set-version.sh 2.2.0
  git commit -am "Bump version to 2.2.0"
  git tag v2.2.0
  git push origin master v2.2.0
  ```

  The workflow stops if the tag and the version numbers don't all match.
- **Dry run.** Running the workflow by hand from the Actions tab does
  everything except the publish.

Every run keeps the packed tarball as the `npm-package` artifact. The
decision logic is in `.github/release-plan.sh`.

The npm package lives in `npm/`. `bin/*.js` are small Node launchers that run
the binary for the platform, `vendor/<platform>/encryptor`, under their own
name, which tells it what to do. `npm/stage.sh` fills `vendor/` in from the
build artifacts.

### When a release fails

The jobs run in order: build and test, publish to npm, then attach the
binaries to the GitHub release. Pushing the same tag again doesn't retry a
release that got as far as npm: the workflow sees the version is already
there and does nothing. Instead:

- **Something went wrong in passing**, such as a network error or a runner
  that died: re-run the failed jobs, from the run's page in the Actions tab
  or with `gh run rerun <run-id> --failed`. They run again with the same
  commit and, after the builds, the same binaries.
- **A build or its tests failed.** Nothing was published. Fix the problem,
  commit, then move the tag to the fix and push it again, which starts a
  new run:

  ```
  git push origin master
  git tag -f v2.2.0
  git push origin :refs/tags/v2.2.0
  git push origin v2.2.0
  ```

- **npm has the version, but attaching the binaries failed.** Re-run the
  failed jobs, as above. If the run is too old for that (its build
  artifacts are kept for 90 days), attach them by hand:

  ```
  gh run download <run-id> -n bin-linux -n bin-macos -D binaries
  gh release create v2.2.0 --verify-tag --title v2.2.0 --notes ""   # if it has no release yet
  gh release upload v2.2.0 binaries/*/encryptor-* --clobber
  ```

Until a release has its binaries, install.sh and `encryptor update` keep
getting the previous one, as long as the new release doesn't exist yet. A
release that exists without them, or with only some, is the latest release,
so installing fails on the systems whose file is missing. For the same
reason, write release notes by editing the release the workflow makes,
rather than publishing one by hand before the workflow has attached the
binaries.

## License

MIT. See the `LICENSE` file.
