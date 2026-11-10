# encryptor

An interactive command-line tool for encrypting and decrypting files with
**AES-256-GCM**, written in Rust.

```
encrypt report.pdf                 # → report.pdf.enc, original securely deleted
decrypt report.pdf.enc             # → report.pdf
encryptor view report.pdf.enc      # shown on screen, erased, then encrypted again
```

Install it on Linux or macOS with:

```
curl -fsSL https://raw.githubusercontent.com/neddyP/encryptor/master/install.sh | sh
```

That downloads the one prebuilt binary for your system, about 1 MB, into
`/usr/local/bin`, and needs nothing else. It can also be installed with npm,
and `encryptor update` updates it either way; see [Install](#install).

## Features

- **AES-256-GCM authenticated encryption.** Any change to an encrypted file,
  even a single bit, is detected and decryption refuses to proceed.
- **View without decrypting to disk.** `encryptor view` shows a file from
  locked memory on a screen of its own, then erases it. Keeping its key
  leaves the file as it was; a new one replaces it. See [Viewing](#viewing).
- **A key or a passphrase.** A 256-bit key from the operating system's
  secure random generator, saved in a folder only you can open, away from
  your files, printed once, or both, and never shown unless you ask. Or your
  own key, as 64 hex characters or a 32-byte key file. Or a passphrase,
  made into a key with Argon2id using 256 MiB of memory, and never saved or
  shown.
- **Printed keys leave no trace.** A printed key goes straight to the
  terminal, never to standard output, on a screen with no scrollback, and is
  erased when you press Enter. Anything that would capture it, such as
  `script`, a sharing tool, tmux `pipe-pane` or a tracer, is named first,
  and you're asked.
- **Verified before anything is deleted.** The encrypted file is read back
  from the disk itself, not the system's cached copy, and decrypted, and the
  original is deleted only if its SHA-256 matches. Decrypted files are
  checked the same way.
- **Original overwritten, then deleted.** It's zeroed, flushed and renamed
  to random characters before it's removed, all through one open handle, so
  swapping in a symlink part way through can't redirect the overwrite. A file
  that can't be overwritten, or that hard links also lead to, is refused
  before any key is made.
- **Nothing left in memory or on disk.** Keys, plaintext and typed input are
  kept in locked RAM and zeroed after use, and so is every other block of
  memory the tool frees. Core dumps are off, and on Linux other programs
  can't read its memory. Unused key files and partial or rejected output are
  zeroed before they're deleted, temporary files have random names, and
  there are no logs.
- **No copies of the original or the key left behind.** On Linux, the
  original's thumbnails, small pictures of its contents, are removed. Any
  bash, zsh or fish history entry holding the key or passphrase a run used is
  removed, including macOS Terminal's history for each window, and what's
  cut is zeroed.
- **Offline unless you update.** Only `encryptor update` goes online, and
  only when you run it.
- **Runs on a screen of its own,** with its name in large letters, wiped
  when you press Enter at the end, leaving your window as it was.
- **Warned about disks that keep old copies.** On a copy-on-write
  filesystem (APFS, btrfs, ZFS) overwriting can't reach the old contents, so
  you're told and asked first.
- **Hidden key entry.** Typed keys and passphrases aren't echoed, and when
  encrypting are entered twice, so a typo can't lock the file for good.
- **Safe to interrupt.** Ctrl-C wipes keys and shreds unused key files and
  partial output, and the original stays unless it was already encrypted and
  verified.
- **Files of any size, in a few megabytes of memory.** Files are encrypted
  in 64 KiB chunks, each authenticated on its own, with a progress bar for
  large ones, and one bar for the whole run when encrypting or decrypting
  several files or a folder.
- **Metadata comes back too.** Permissions, times, owner and extended
  attributes (ACLs, Finder tags, download quarantine) are stored inside the
  encryption and restored. Any file type works: the tool only sees bytes.
- **Errors that say how to fix them,** with commands to paste using your own
  file names. A missing file suggests the one you meant, a full or read-only
  disk or FAT32's size limit is named, a file that isn't encrypted is
  identified (a zip, a PDF, or a file from OpenSSL, GPG or age), and a
  mistyped key is described without being shown.
- **Crash-safe writes.** Output is written under a temporary name and
  renamed into place, so a half-written file never has the final name.

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
only with curl or GNU wget, checks it against the release's `SHA256SUMS`, and
refuses it if it doesn't match. Then it installs it as
`/usr/local/bin/encryptor`, with `encrypt` and `decrypt` linked to it. If you can't write to `/usr/local/bin` yourself,
as usual unless you're root, it uses sudo for that, which asks for your
password. On a system without sudo, it installs into `~/.local/bin` instead,
for you alone, and tells you how to add that folder to your `PATH` if it isn't
there yet. The binary is statically linked, so it runs on any distribution
and needs nothing else installed.

The checksum catches a damaged or altered download, but it comes from the
same release as the binary. To check the binary was built by this
repository's release workflow from its source, with the
[GitHub CLI](https://cli.github.com):

```
gh attestation verify /usr/local/bin/encryptor --repo neddyP/encryptor
```

The npm package carries the same kind of record, shown as provenance on its
npm page.

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
Node.js 16 or newer. npm installs only the prebuilt binary for your system,
about 1 MB, so you don't need Rust.

```
npm install -g @neddyp/encryptor
```

That puts `encrypt`, `decrypt` and `encryptor` on your `PATH`. Check it
worked:

```
encryptor --help
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

`bin/encrypt`, `bin/decrypt` and `bin/encryptor` are symlinks to `target/release/encryptor`, so rebuilding updates them
automatically. After a
`cargo clean`, run `cargo build --release` again to bring them back.

A copy built from source is updated by pulling the latest source and
building it again; `encryptor update` says so rather than replacing it. If
you also installed it another way, whichever `encrypt` comes first on your
`PATH` is the one that runs. `type -a encrypt` lists them all.

## Usage

```
encrypt FILE... [OPTIONS]      encrypt each FILE to FILE.enc, then delete it
encrypt -r FOLDER [OPTIONS]    encrypt every file in FOLDER and its subfolders
decrypt FILE.enc... [OPTIONS]  decrypt each FILE.enc back to FILE
decrypt -r FOLDER [OPTIONS]    decrypt every .enc file in FOLDER and its
                               subfolders, all with one key
encryptor view FILE.enc        show FILE.enc decrypted on screen, then
                               erase it and encrypt it again
encryptor                      show the home screen
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
`encrypt` and `decrypt`, and `encryptor -v FILE.enc` (or `decrypt -v`) the
same as `encryptor view`; see [Viewing](#viewing). Each option answers one of
the questions in advance, so it isn't asked:

| Option                | What it does                                                        |
| --------------------- | ------------------------------------------------------------------- |
| `-r`, `--recursive`   | Take in every file in the folders given and their subfolders; decrypt takes `.enc` files only |
| `-k`, `--key-file KEY` | Use the key in `KEY`: 32 bytes, or 64 hex characters. It can be a pipe |
| `--new-key PATH`      | Encrypt with a new key, saved to `PATH`, or into `PATH` if it's a folder |
| `--keep`              | Encrypt, but keep the original instead of deleting it               |
| `-o`, `--output PATH` | Decrypt to `PATH` instead of next to the encrypted file            |
| `--overwrite`         | Decrypt over the output file if it already exists                   |
| `-v`, `--view`        | View the file instead of decrypting it to disk                      |
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
`v` to view one, or `q` to quit; the arrow keys scroll if it doesn't all
fit. Without a terminal it asks "Encrypt or decrypt?" instead.

If you leave out `FILE`, you're asked for it, or with `-r`, for the folder. Typed paths may be quoted or
start with `~/`, so you can drag a file into the terminal.

Questions, warnings and errors go to standard error, and only the final
report to standard output, so `encrypt report.pdf > report.txt` still shows
every question and saves just the report. With its output redirected like
this, it runs in the window itself rather than on a screen of its own.

### Several files and folders

`encrypt` and `decrypt` take any number of files, and with `-r` every file
in the folders given and in all their subfolders, hidden files too:

```
encrypt ~/report.pdf ~/list.md ~/data.xlsx
encrypt -r ~/Documents/taxes
decrypt -r ~/Documents/taxes
```

Each file is encrypted to its own `.enc` file beside it, and its original
destroyed, exactly as for one file. After `Use a 256-bit key or a custom
passphrase? [ky/ps]` comes one more question:

```
Use one universal key for all 3 files, or a separate key for each? [u/s]:
```

- **`u`, universal:** one key for every file. A saved key is named after the
  folder: `taxes.key` for `encrypt -r ~/Documents/taxes`, and for files named
  one by one, the folder they're all in: `you.key` for the example above,
  with a home folder of `/home/you`. With a passphrase, it's one passphrase for all of them.
- **`s`, separate:** each file gets its own key, saved as `<file>.key` (a
  number is added when two files share a name), or its own passphrase. The
  save and print questions are asked once, for all the keys. Keys you type,
  and passphrases, are asked for file by file as each is reached.

`--key-file` and `--new-key` give one universal key, so the question isn't
asked. Every file is checked before any key is made: if one can't be
encrypted, as when its `.enc` file already exists, nothing is done and the
problems are listed. Then the files are done in turn, and if one fails, the
run stops there, saying how many were done; the rest are left as they were.

Going through folders, `encrypt` leaves out files already ending in `.enc`,
symbolic links (which aren't followed, so nothing outside the folder is
reached), anything that isn't a regular file, the keys folder, and the key
file in use, since encrypting a key would lock it inside the files it opens.
The report says what was left out.

`decrypt` with several files asks the same `[u/s]` question: answer `u` to
give one key or passphrase for all of them, or `s` to give each file's in
turn. Files encrypted with a passphrase and files encrypted with a key can't
share one, so given both, it asks for each in turn. `decrypt -r` only takes
one universal key or passphrase for every `.enc` file in the folder, and
refuses a folder holding both kinds.

A passphrase is made into each file's key with that file's own salt, so
Argon2id runs once per file, about a second each on a recent desktop. For a
folder of hundreds of files, a universal key is much faster.

### Encrypting

```
$ encrypt report.pdf
Use a 256-bit key or a custom passphrase? [ky/ps]: ky
Generate a random 256-bit key? [y/n]: y
Key generated (not displayed).
Save the key to a file in ~/.local/share/encryptor/keys? [y/n]: y
Key saved as: ~/.local/share/encryptor/keys/report.pdf.key
Keep it safe: anyone with it can decrypt the file, and without it no one can.
Print the key? [y/n]: n
Encrypt using AES-256-GCM? [y/n]: y

----------------------------------------------------------------
  ENCRYPTION SUCCESSFUL
----------------------------------------------------------------
  Cipher         AES-256-GCM (authenticated encryption)
  Key            256-bit, generated by the OS CSPRNG
  Key storage    saved to /home/you/.local/share/encryptor/keys/report.pdf.key (owner read/write only)
  File key       derived with HKDF-SHA256 from the key and a random 256-bit salt
  Chunks         20 of up to 64 KiB, each with its own 128-bit auth tag
  Input          report.pdf  1258291 bytes (1.2 MiB)
  Output         report.pdf.enc  1258725 bytes (1.2 MiB)
  Overhead       434 bytes (37 header + 77 metadata + 320 in tags)
  Metadata       stored encrypted: permissions 644, owner 1000:1000, accessed, modified and created times
  Integrity      verified: re-read from disk, decrypted, SHA-256 matches original
  Original       overwritten with zeros, name scrambled, then deleted
  Thumbnails     removed 1
  Key and data   kept in RAM (never swapped), wiped after use
  Shell history  no entries held the key
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
1. **A key or a passphrase?** `ky` goes on to the key questions below. `ps`
   asks for a passphrase, twice, as it isn't shown, and skips them: a
   passphrase is never saved to a file or printed. It needs at least 12
   characters, with a capital, a lowercase letter, a number and a special
   character such as `!` or `#`. Anyone with the encrypted file can try
   guesses at it, so use a long one, such as five or more random words. It's
   made into the key with Argon2id (256 MiB, 3 passes, about half a second),
   in memory that's wiped afterwards, and locked out of swap where the system
   allows that much (most only let a program lock 8 MiB). The file is written
   in [format 4](#file-format), which records those settings, so files made
   with the earlier 7 MiB settings still open. encryptor 2.5.1 and earlier
   can't open files made with these settings unless run as root.
2. **Generate a random key?** Answer `n` to enter your own key instead; the
   save and print questions are then skipped.
3. **Save the key as a file?** `y` saves it as a 32-byte binary file named
   `<file>.key` (with a number added if that's taken) in
   `~/.local/share/encryptor/keys`, or `$XDG_DATA_HOME/encryptor/keys`. Only
   you can open that folder, and it's away from your files, so copying,
   backing up or syncing their folder doesn't take the key with them. To
   save a key somewhere else, use `--new-key PATH`; you're warned if that's
   beside the encrypted file.
4. **Print the key?** `y` clears the screen and shows the key once as 64
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
5. **Encrypt?** `n` cancels. A key file saved earlier is then removed, since
   it never encrypted anything.
6. **Save this summary?** `y` saves the report as `encryption-summary.txt`
   in the current directory, readable only by you (a number is added if the
   name is taken). It's only asked at a terminal, and not with `--yes` or `--quiet`, so scripts never wait for it.
7. **Press Enter to exit and wipe this screen.** Everything encryptor showed
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
Printing the key would save it to script, compromising your encryption. Print it anyway? [y/n]: n
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
Enter the key (64 hex characters) or the path to its key file:
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
  Shell history  no entries held the key
  Time           10.90ms
----------------------------------------------------------------
```

At the key prompt, either type or paste the hex key, or give the path to the
key file. A bare name like `report.pdf.key` is also looked for in the keys
folder, where new keys are saved. Neither is echoed. You get three attempts.
A file encrypted with a passphrase asks `Enter the passphrase:` instead, and
`--key-file` doesn't apply to it. As after encrypting, you're then offered to save the summary, as
`decryption-summary.txt`, and Enter exits and
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

### Viewing

`encryptor view` shows an encrypted file without ever decrypting it to disk:

```
$ encryptor view report.txt.enc
Enter the key (64 hex characters) or the path to its key file:

Before it's shown:
  - It's held only in locked memory, never written to swap or disk, and
    shown on a screen of its own with no scrollback. When you press Enter,
    it's erased and encrypted again.
  - Anyone who can see your screen, or a screenshot, screen share or
    recording of it, sees the file too.
  - Selecting text copies it to your clipboard, and clipboard history
    keeps it.
  - Your terminal program holds what it shows in its own memory, which
    this tool can't wipe.
Show the decrypted file? [y/n]: y
```

The decrypted file only ever exists in locked memory, which is never written
to swap, and on the terminal. Everything the
plaintext passes through is locked: the file's buffer, the chunk being
decrypted, its stored metadata, each screenful and the stack. If any of it
can't be locked, view stops before putting plaintext there. It's shown on a
screen of its own with its name at the top. The arrow keys, PgUp, PgDn, Home
and End scroll it. Long lines wrap at the window's edge. As with a printed
key, it's written straight to the terminal, never to standard output, so
redirecting the output can't capture it, and each screenful is built in
locked memory and wiped as soon as it's drawn.

Control characters in the file, such as Escape, are shown as `^[` and the
like rather than sent to the terminal, so a file can't clear the screen,
retitle the window or write to the clipboard through escape sequences of
its own. Direction overrides, which reorder the text around them, are shown
escaped too. A file that isn't text is shown as a hex dump.

Press Enter (or `q`, or Escape) when you're done, and the screen is erased.
Then you keep its key, or encrypt it again with a new one:

```
The file was shown, then erased from the screen.

Keep its key, or encrypt it again with a new one:
  s  keep the same key, from report.txt.key, and leave the file as it was
  n  a new key or passphrase, replacing report.txt.enc
Same key or a new one? [s/n]:
```

- **`s`** leaves the file exactly as it was. Encrypting it again with the
  same key wouldn't change who can open it, so nothing is written.
- **`n`** asks the key questions from scratch, as `encrypt` asks them: a
  passphrase or a key, generated and saved or printed, or one you enter.
  The file is encrypted again where it is, with a new salt and its original
  metadata, and read back from disk and checked before it replaces the old
  one. The old key or passphrase no longer opens it.

If the file's folder can't be written to, it's left as it was, and you're
told why instead of being asked. If you decide not to view it at `Show the
decrypted file?`, nothing is written. Ctrl-C at any point stops without
writing anything, and leaves the encrypted file as it was.

Viewing needs someone at the keyboard, so `view` refuses to run from a script
(status 2). It only takes `--key-file` and `--quiet`. If something is
[recording the session](#when-the-session-is-being-recorded), it's named
first and you're asked `Showing the file would save its contents to script.
Show it anyway?`.

The whole file is held in locked memory, so as soon as view has the file's
name, it checks how much more memory it can lock: the system's limit
(`ulimit -l`, often 8 MiB on Linux) less what it has locked already, and no
more than the memory that's free. Root isn't held to the limit. If the file
doesn't fit, with about 1 MiB to work in, it isn't viewed, and no key is
asked for:

```
film.mp4.enc is 12.0 MiB, too large to view: view keeps the decrypted file in locked
memory, which is never written to swap, and there's only room to lock files of up to
7.0 MiB now.
Decrypting writes it to film.mp4 instead, as plaintext on disk until you encrypt it
again. To view larger files, an administrator can raise the memory lock limit
(memlock, in /etc/security/limits.conf).
Decrypt it to a file, or quit? [d/q]:
```

`d` decrypts it just as `decrypt` would, beside the encrypted file, asking
for the key then, or using `--key-file`. `q` quits without writing anything.
Files over 4 GiB can't be viewed at all.

### Scripting

In scripts, give options rather than answers, so nothing is asked:

```
encrypt report.pdf --new-key ~/keys/ --yes                 # new key saved as ~/keys/report.pdf.key
encrypt backup.tar --key-file ~/keys/backup.key --keep -y  # encrypt a copy, keep the original
decrypt report.pdf.enc --key-file ~/keys/report.pdf.key --yes
decrypt report.pdf.enc --key-file <(pass show keys/report) --yes   # key from a password manager
encrypt -r photos --new-key ~/keys/photos.key --yes        # every file in photos, one key
decrypt -r photos --key-file ~/keys/photos.key --yes
```

Keys are never given on the command line itself, since every user can see
command lines and the shell saves them in its history. `--key-file` takes a
32-byte key file, or 64 hex characters as `encrypt` prints them, and can be a
pipe, so a key from a password manager never touches the disk. Passphrases
are for people at the keyboard: there's no option for one, so scripts use
keys.

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
the questions are asked, but print a note, and stop working in 4.0. Which
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

A file encrypted with a passphrase is version `4`, with 12 more bytes before
the salt: Argon2id's memory in KiB, passes and lanes, each a little-endian
u32. Its header is 49 bytes, and its key is Argon2id (version 19) of the
passphrase, as typed in UTF-8, with those settings and the file's salt, 32
bytes long. Everything else is as in version 3.

The plaintext is split into chunks of 64 KiB, and only the last may be
shorter. Each is encrypted with AES-256-GCM and followed by its 16-byte tag,
so a full chunk takes 65,552 bytes on disk.

- **Key.** Each file has its own AES key, derived from your key and the salt
  with HKDF-SHA256 (info `encryptor v3 file key`). So no two files share a
  key, even when you reuse yours.
- **Nonces.** Chunk *n* (counting from 0) uses the 12-byte nonce made of *n*
  as an 11-byte big-endian number, then `1` for the last chunk or `0` for any
  other.
- **Associated data.** The header is the associated data of every chunk, so
  it is authenticated too.

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
file. Earlier versions can't read formats newer than theirs, such as a
passphrase's version 4; they say so, and how to update.

| Version | Made by     | Layout                                                    |
| ------- | ----------- | --------------------------------------------------------- |
| 2       | 2.0         | `AGCM`, `2`, 12-byte random nonce, ciphertext, 16-byte tag |
| 1       | before 2.0  | The same, with version `1` and no metadata                 |

In both, the 17-byte header is the associated data. Version 2's plaintext
starts with the metadata, as above; version 1's is just the contents.

## Security notes

- **Lose the key, lose the file.** There's no recovery or backdoor, and a
  forgotten passphrase is as lost as a key. Generated keys are saved in the
  keys folder, away from the encrypted files; back that folder up somewhere
  safe, apart from the files.
- **Overwriting isn't guaranteed to erase.** SSD wear levelling, copy-on-write
  filesystems (APFS, btrfs, ZFS), snapshots and backups can keep old copies
  of the original, and of history files and thumbnails the tool overwrites.
  Full-disk encryption is the reliable protection for those.
- **It doesn't hide that it ran.** Shell history keeps the commands that
  ran it, file and folder timestamps show when it ran, your desktop's list of
  recently used files keeps the original's name, and a saved summary names
  the files. Only the key, passphrase and the original's contents are
  removed. To keep a command out of history, start it with a space: bash does
  that with `HISTCONTROL=ignorespace` (or `ignoreboth`, Ubuntu's default),
  zsh with `setopt HIST_IGNORE_SPACE`, and fish always.
- **Some copies are out of the tool's reach.** It removes what it can find,
  but copies can still be kept in:
  - **A key typed into the command that ran it.** Shells keep their own
    session's history in memory and save it when they exit, after the tool
    has finished, so it's only removed by a later run that uses that key.
    Other shells left open can also write back entries they read when they
    started.
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
- **Viewing a file shows it to whatever can see your screen.** `view` keeps
  the decrypted file off the disk and out of scrollback, but screenshots,
  screen sharing and recorders it can't detect see what's on the screen, and
  the terminal program holds it in memory while it's shown. Text selected on
  the screen goes onto the clipboard. Locked memory stays out of swap, but a
  computer that hibernates or suspends to disk while a file is shown writes
  all of memory to the disk, so use full-disk encryption there too.
- **A passphrase is only as strong as it is long.** Argon2id makes each
  guess cost time and memory, but anyone with the file can keep guessing.
  Use five or more random words, or a generated key. A key you enter is used
  as it is, so it should be random, not something memorable.
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
Argon2id against another implementation, passphrase files end to end, the
keys folder,
overwriting and deleting files (including when a file is swapped for a
symlink part way through, is read-only, or has other names), removing shell
history entries holding a key, thumbnails, escaping of untrusted file
names, laying out a viewed file and showing its control characters instead of
obeying them, recognising recorders and the files they write to, storing and restoring
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
| `batch.rs`     | Several files and folders (`-r`), with universal or separate keys    |
| `view.rs`      | The view command, then keeping the key or encrypting it again        |
| `pager.rs`     | Showing a decrypted file on a screen of its own, then erasing it     |
| `keys.rs`      | Generating, saving, printing and entering keys, and passphrases      |
| `history.rs`   | Removing keys and passphrases from shell history                     |
| `desktop.rs`   | Removing the original's thumbnails                                   |
| `stream.rs`    | Chunked encryption, format versions 3 and 4                          |
| `kdf.rs`       | Keys from passphrases, with Argon2id                                 |
| `legacy.rs`    | Decrypting format versions 1 and 2                                   |
| `meta.rs`      | The stored metadata                                                  |
| `files.rs`     | Checking input, reading back from disk, writing output safely        |
| `wipe.rs`      | Secure deletion, and rewriting files in place                        |
| `term.rs`      | Terminal input and output, prompts                                   |
| `progress.rs`  | Progress bars, for large files and for a whole batch                 |
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
[`hkdf`](https://crates.io/crates/hkdf),
[`sha2`](https://crates.io/crates/sha2) and
[`argon2`](https://crates.io/crates/argon2) crates,
[`zeroize`](https://crates.io/crates/zeroize) for wiping secrets,
[`getrandom`](https://crates.io/crates/getrandom) for randomness,
[`md-5`](https://crates.io/crates/md-5) for finding thumbnails by name and
[`libc`](https://crates.io/crates/libc) for the system calls.

## Releasing

Releases are built and published by `.github/workflows/release.yml`, using
npm trusted publishing so no npm token is stored in the repo. Each release
tests and builds static Linux binaries (x64, arm64, and 32-bit x86 and arm)
and macOS binaries (x64 and arm64). The x64 and arm64 ones go to npm, each in
a package of its own, and all six are attached to the version's GitHub release as
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

Every run keeps the packed tarballs as the `npm-package` artifact. The
decision logic is in `.github/release-plan.sh`.

The npm package lives in `npm/`. `bin/*.js` are small Node launchers that run
the binary for the platform under their own name, which tells it what to do.
Each binary is in a package of its own, `@neddyp/encryptor-<platform>`,
limited by its `os` and `cpu` to the systems it runs on. `@neddyp/encryptor`
names all four as optional dependencies, at its own version, and npm
installs only the one that fits. `npm/stage.sh` makes them in
`npm/platforms/` from the build artifacts, and the workflow publishes them
before `@neddyp/encryptor`.

A new platform package needs publishing once by hand before the workflow
can publish it, as npm only lets a package that exists name a trusted
publisher: publish a placeholder version with `npm publish --access public`,
then in the package's settings on npmjs.com add the trusted publisher
(GitHub Actions, `neddyP`, `encryptor`, `release.yml`).

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
  mv binaries/*/encryptor-* binaries/
  (cd binaries && sha256sum encryptor-* > SHA256SUMS)
  gh release create v2.2.0 --verify-tag --title v2.2.0 --notes ""   # if it has no release yet
  gh release upload v2.2.0 binaries/encryptor-* binaries/SHA256SUMS --clobber
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
