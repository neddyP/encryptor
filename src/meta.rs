//! The original file's metadata: permissions, owner, timestamps and extended
//! attributes. It is encrypted along with the contents, at the start of the
//! plaintext, and put back on the decrypted file.
//!
//! The encoding is a 4-byte little-endian length, then that many bytes of
//! records, each a 1-byte tag, a 4-byte little-endian length and the value.
//! Unknown tags are skipped, so later versions can add records.

use std::ffi::CString;
use std::fs::{File, FileTimes, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::explain::listed;
use crate::term::safe;

const MODE: u8 = 1;
const OWNER: u8 = 2;
const ACCESSED: u8 = 3;
const MODIFIED: u8 = 4;
const CREATED: u8 = 5;
const XATTR: u8 = 6;

/// Permission bits, including setuid, setgid and sticky.
const MODE_BITS: u32 = 0o7777;
const SETUID_SETGID: u32 = 0o6000;

/// A timestamp as seconds and nanoseconds since 1970, like `struct timespec`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Time {
    secs: i64,
    nanos: u32,
}

impl Time {
    fn from_system(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Self { secs: after.as_secs() as i64, nanos: after.subsec_nanos() },
            Err(e) => {
                let before = e.duration();
                match before.subsec_nanos() {
                    0 => Self { secs: -(before.as_secs() as i64), nanos: 0 },
                    n => Self { secs: -(before.as_secs() as i64) - 1, nanos: 1_000_000_000 - n },
                }
            }
        }
    }

    fn to_system(self) -> Option<SystemTime> {
        let whole = Duration::from_secs(self.secs.unsigned_abs());
        let base = if self.secs < 0 { UNIX_EPOCH.checked_sub(whole) } else { UNIX_EPOCH.checked_add(whole) };
        base?.checked_add(Duration::from_nanos(self.nanos.into()))
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Metadata {
    mode: Option<u32>,
    owner: Option<(u32, u32)>,
    accessed: Option<Time>,
    modified: Option<Time>,
    created: Option<Time>,
    /// Extended attributes by name. Values can be as private as the contents.
    xattrs: Vec<(CString, Zeroizing<Vec<u8>>)>,
}

impl Metadata {
    /// Reads the metadata of an open file. Extended attributes that can't be
    /// read are left out.
    pub fn capture(file: &File) -> io::Result<Self> {
        let meta = file.metadata()?;
        Ok(Self {
            mode: Some(meta.mode() & MODE_BITS),
            owner: Some((meta.uid(), meta.gid())),
            accessed: meta.accessed().ok().map(Time::from_system),
            modified: meta.modified().ok().map(Time::from_system),
            created: meta.created().ok().map(Time::from_system),
            xattrs: xattr::list(file).unwrap_or_default(),
        })
    }

    /// Calls `record` with each record's tag and value, in pieces.
    fn records(&self, mut record: impl FnMut(u8, &[&[u8]])) {
        if let Some(mode) = self.mode {
            record(MODE, &[&mode.to_le_bytes()]);
        }
        if let Some((uid, gid)) = self.owner {
            record(OWNER, &[&uid.to_le_bytes(), &gid.to_le_bytes()]);
        }
        for (tag, time) in [(ACCESSED, self.accessed), (MODIFIED, self.modified), (CREATED, self.created)] {
            if let Some(time) = time {
                record(tag, &[&time.secs.to_le_bytes(), &time.nanos.to_le_bytes()]);
            }
        }
        for (name, value) in &self.xattrs {
            record(XATTR, &[name.as_bytes(), &[0], value]);
        }
    }

    pub fn encoded_len(&self) -> usize {
        let mut len = 4;
        self.records(|_, parts| len += 5 + parts.iter().map(|part| part.len()).sum::<usize>());
        len
    }

    /// Encodes into `out`, which must be exactly `encoded_len()` bytes. Writes
    /// in place, so the secret buffer it goes into is never copied.
    pub fn encode(&self, out: &mut [u8]) {
        let len = (out.len() - 4) as u32;
        out[..4].copy_from_slice(&len.to_le_bytes());
        let mut at = 4;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        self.records(|tag, parts| {
            put(&[tag]);
            put(&(parts.iter().map(|part| part.len()).sum::<usize>() as u32).to_le_bytes());
            for part in parts {
                put(part);
            }
        });
    }

    /// Reads metadata from the start of decrypted data. Returns it and how
    /// many bytes it took up.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        let damaged = || "the metadata stored in the file is damaged".to_string();
        let len = u32::from_le_bytes(fixed(data.get(..4)).ok_or_else(damaged)?) as usize;
        let end = len.checked_add(4).ok_or_else(damaged)?;
        let mut rest = data.get(4..end).ok_or_else(damaged)?;

        let mut meta = Self::default();
        while let Some((&tag, after)) = rest.split_first() {
            let value_len = u32::from_le_bytes(fixed(after.get(..4)).ok_or_else(damaged)?) as usize;
            let value = after.get(4..).and_then(|v| v.get(..value_len)).ok_or_else(damaged)?;
            rest = &after[4 + value_len..];
            let time = || {
                let (secs, nanos) = value.split_at_checked(8)?;
                Some(Time { secs: i64::from_le_bytes(fixed(Some(secs))?), nanos: u32::from_le_bytes(fixed(Some(nanos))?) })
            };
            match tag {
                MODE => meta.mode = Some(u32::from_le_bytes(fixed(Some(value)).ok_or_else(damaged)?)),
                OWNER => {
                    let (uid, gid) = value.split_at_checked(4).ok_or_else(damaged)?;
                    let id = |bytes| fixed(Some(bytes)).map(u32::from_le_bytes).ok_or_else(damaged);
                    meta.owner = Some((id(uid)?, id(gid)?));
                }
                ACCESSED => meta.accessed = Some(time().ok_or_else(damaged)?),
                MODIFIED => meta.modified = Some(time().ok_or_else(damaged)?),
                CREATED => meta.created = Some(time().ok_or_else(damaged)?),
                XATTR => {
                    let nul = value.iter().position(|&b| b == 0).ok_or_else(damaged)?;
                    let name = CString::new(&value[..nul]).map_err(|_| damaged())?;
                    meta.xattrs.push((name, Zeroizing::new(value[nul + 1..].to_vec())));
                }
                _ => {}
            }
        }
        Ok((meta, end))
    }

    /// Describes what is stored, for the report.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(mode) = self.mode {
            parts.push(format!("permissions {mode:03o}"));
        }
        if let Some((uid, gid)) = self.owner {
            parts.push(format!("owner {uid}:{gid}"));
        }
        let times = [("accessed", self.accessed), ("modified", self.modified), ("created", self.created)];
        let times: Vec<&str> = times.iter().filter(|(_, time)| time.is_some()).map(|(name, _)| *name).collect();
        if !times.is_empty() {
            parts.push(format!("{} times", listed(&times)));
        }
        if !self.xattrs.is_empty() {
            parts.push(count(self.xattrs.len(), "extended attribute"));
        }
        parts.join(", ")
    }

    /// Puts the metadata back on `file` as far as this user is allowed to,
    /// and describes what was and wasn't restored.
    pub fn restore(&self, file: &File) -> String {
        let mut restored = Vec::new();
        let mut missed = Vec::new();

        // Owner first, since changing it clears setuid, setgid and file
        // capabilities. Those are privileges, so they are restored only along
        // with the original owner, as `cp -p` does.
        let mut same_owner = true;
        if let (Some((uid, gid)), Ok(now)) = (self.owner, file.metadata()) {
            if (uid, gid) != (now.uid(), now.gid()) {
                if std::os::unix::fs::fchown(file, Some(uid), Some(gid)).is_ok() {
                    restored.push(format!("owner {uid}:{gid}"));
                } else {
                    if uid != now.uid() {
                        same_owner = false;
                        missed.push(format!("owner {uid} (only root can give a file away)"));
                    }
                    if gid != now.gid() {
                        match std::os::unix::fs::fchown(file, None, Some(gid)) {
                            Ok(()) => restored.push(format!("group {gid}")),
                            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                                missed.push(format!("group {gid} (you aren't a member of it)"));
                            }
                            Err(e) => missed.push(format!("group {gid} ({e})")),
                        }
                    }
                }
            }
        }

        let mut set = 0;
        for (name, value) in &self.xattrs {
            if !same_owner && name.as_bytes() == b"security.capability" {
                missed.push("file capabilities (they need the original owner)".into());
                continue;
            }
            match xattr::set(file, name, value) {
                Ok(()) => set += 1,
                Err(e) => missed.push(format!("extended attribute {} ({e})", safe(&name.to_string_lossy()))),
            }
        }
        if let Some(mode) = self.mode {
            let wanted = if same_owner { mode } else { mode & !SETUID_SETGID };
            let _ = file.set_permissions(Permissions::from_mode(wanted));
            // The system can quietly drop setgid, so report what it kept.
            match file.metadata().map(|meta| meta.mode() & MODE_BITS) {
                Ok(now) if now == mode => restored.push(format!("permissions {mode:03o}")),
                Ok(now) => missed.push(format!("permissions {mode:03o} (set to {now:03o})")),
                Err(e) => missed.push(format!("permissions {mode:03o} ({e})")),
            }
        }

        // Times last, after everything that could change them.
        let mut times = FileTimes::new();
        let mut names = Vec::new();
        if let Some(accessed) = self.accessed.and_then(Time::to_system) {
            times = times.set_accessed(accessed);
            names.push("accessed");
        }
        if let Some(modified) = self.modified.and_then(Time::to_system) {
            times = times.set_modified(modified);
            names.push("modified");
        }
        #[cfg(target_os = "macos")]
        if let Some(created) = self.created.and_then(Time::to_system) {
            use std::os::macos::fs::FileTimesExt;
            times = times.set_created(created);
            names.push("created");
        }
        #[cfg(not(target_os = "macos"))]
        if self.created.is_some() {
            missed.push("created time (this system can't set it)".into());
        }
        if !names.is_empty() {
            match file.set_times(times) {
                Ok(()) => restored.push(format!("{} times", listed(&names))),
                Err(e) => missed.push(format!("{} times ({e})", listed(&names))),
            }
        }
        if set > 0 {
            restored.push(count(set, "extended attribute"));
        }

        let mut status = match restored.is_empty() {
            true => "nothing restored".to_string(),
            false => format!("restored {}", restored.join(", ")),
        };
        if !missed.is_empty() {
            status.push_str(&format!("; not restored: {}", missed.join(", ")));
        }
        status
    }
}

fn fixed<const N: usize>(bytes: Option<&[u8]>) -> Option<[u8; N]> {
    bytes?.try_into().ok()
}

fn count(n: usize, thing: &str) -> String {
    if n == 1 { format!("1 {thing}") } else { format!("{n} {thing}s") }
}

/// Extended attributes, read and written through an open file.
mod xattr {
    use super::*;

    /// Every extended attribute of `file` that can be read.
    pub fn list(file: &File) -> io::Result<Vec<(CString, Zeroizing<Vec<u8>>)>> {
        let fd = file.as_raw_fd();
        let names = read(|buf| sys::list(fd, buf))?;
        let mut attrs = Vec::new();
        for name in names.split(|&b| b == 0).filter(|name| !name.is_empty()) {
            let name = CString::new(name).expect("names are split at NULs");
            // One that vanished or can't be read since the list was made is
            // left out.
            if let Ok(value) = read(|buf| sys::get(fd, &name, buf)) {
                attrs.push((name, value));
            }
        }
        Ok(attrs)
    }

    pub fn set(file: &File, name: &CString, value: &[u8]) -> io::Result<()> {
        match sys::set(file.as_raw_fd(), name, value) {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Calls `get` with an empty buffer to learn the size, then again with a
    /// buffer of exactly that size, so it never grows and leaves copies
    /// behind. Tries again if the value grew in between.
    fn read(mut get: impl FnMut(&mut [u8]) -> libc::ssize_t) -> io::Result<Zeroizing<Vec<u8>>> {
        let size = |n: libc::ssize_t| usize::try_from(n).map_err(|_| io::Error::last_os_error());
        for _ in 0..8 {
            let mut buf = Zeroizing::new(vec![0u8; size(get(&mut []))?]);
            crate::protect::lock(buf.as_ptr(), buf.len());
            match size(get(&mut buf)) {
                Ok(n) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Err(e) if e.raw_os_error() == Some(libc::ERANGE) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::from_raw_os_error(libc::ERANGE))
    }

    // SAFETY, for all of these: each buffer is valid for its length and each
    // name is NUL-terminated. macOS takes extra position and option
    // arguments, 0 for a whole value and default behaviour.

    #[cfg(target_os = "linux")]
    mod sys {
        use std::ffi::CStr;

        pub fn list(fd: libc::c_int, buf: &mut [u8]) -> libc::ssize_t {
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) }
        }
        pub fn get(fd: libc::c_int, name: &CStr, buf: &mut [u8]) -> libc::ssize_t {
            unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
        }
        pub fn set(fd: libc::c_int, name: &CStr, value: &[u8]) -> libc::c_int {
            unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) }
        }
    }

    #[cfg(target_os = "macos")]
    mod sys {
        use std::ffi::CStr;

        pub fn list(fd: libc::c_int, buf: &mut [u8]) -> libc::ssize_t {
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len(), 0) }
        }
        pub fn get(fd: libc::c_int, name: &CStr, buf: &mut [u8]) -> libc::ssize_t {
            unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), 0, 0) }
        }
        pub fn set(fd: libc::c_int, name: &CStr, value: &[u8]) -> libc::c_int {
            unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0, 0) }
        }
    }

    /// Elsewhere, no extended attributes are kept.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    mod sys {
        use std::ffi::CStr;

        pub fn list(_: libc::c_int, _: &mut [u8]) -> libc::ssize_t {
            0
        }
        pub fn get(_: libc::c_int, _: &CStr, _: &mut [u8]) -> libc::ssize_t {
            0
        }
        pub fn set(_: libc::c_int, _: &CStr, _: &[u8]) -> libc::c_int {
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Metadata {
        Metadata {
            mode: Some(0o4751),
            owner: Some((1000, 20)),
            accessed: Some(Time { secs: 1_000_000_000, nanos: 123_456_789 }),
            modified: Some(Time { secs: -1, nanos: 500_000_000 }),
            created: None,
            xattrs: vec![
                (CString::new("user.comment").unwrap(), Zeroizing::new(b"binary\0value\xff".to_vec())),
                (CString::new("user.empty").unwrap(), Zeroizing::new(Vec::new())),
            ],
        }
    }

    fn encode(meta: &Metadata) -> Vec<u8> {
        let mut out = vec![0; meta.encoded_len()];
        meta.encode(&mut out);
        out
    }

    #[test]
    fn round_trips_through_the_encoding() {
        let meta = sample();
        let mut data = encode(&meta);
        let len = data.len();
        data.extend_from_slice(b"file contents");
        assert_eq!(Metadata::parse(&data).unwrap(), (meta, len));

        let empty = encode(&Metadata::default());
        assert_eq!(empty, [0, 0, 0, 0]);
        assert_eq!(Metadata::parse(&empty).unwrap(), (Metadata::default(), 4));
    }

    #[test]
    fn skips_records_it_does_not_know() {
        let mut data = encode(&sample());
        data.extend_from_slice(&[99, 3, 0, 0, 0, 1, 2, 3]);
        let len = (data.len() - 4) as u32;
        data[..4].copy_from_slice(&len.to_le_bytes());
        assert_eq!(Metadata::parse(&data).unwrap().0, sample());
    }

    #[test]
    fn rejects_damaged_metadata() {
        let data = encode(&sample());
        for cut in [0, 3, 4, 10, data.len() - 1] {
            assert!(Metadata::parse(&data[..cut]).is_err(), "cut at {cut}");
        }
        // A record running past the end of the metadata.
        let mut long = data.clone();
        long[5..9].copy_from_slice(&1000u32.to_le_bytes());
        assert!(Metadata::parse(&long).is_err());
        // A mode that isn't 4 bytes.
        assert!(Metadata::parse(&[6, 0, 0, 0, MODE, 1, 0, 0, 0, 7]).is_err());
    }

    #[test]
    fn converts_times_before_and_after_1970() {
        for time in [Time { secs: 1_700_000_000, nanos: 1 }, Time { secs: -2, nanos: 999_999_999 }, Time { secs: 0, nanos: 0 }] {
            assert_eq!(Time::from_system(time.to_system().unwrap()), time);
        }
    }

    #[test]
    fn restores_what_it_captured() {
        let dir = std::env::temp_dir().join(format!("aes256-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"x").unwrap();
        std::fs::write(&to, b"x").unwrap();

        let source = File::open(&from).unwrap();
        let xattrs = xattr::set(&source, &CString::new("user.aes256-test").unwrap(), b"\0tag\xff").is_ok();
        source.set_permissions(Permissions::from_mode(0o751)).unwrap();
        let accessed = UNIX_EPOCH + Duration::new(1_000_000_000, 123_456_789);
        let modified = UNIX_EPOCH + Duration::new(1_234_567_890, 987_654_321);
        source.set_times(FileTimes::new().set_accessed(accessed).set_modified(modified)).unwrap();
        let captured = Metadata::capture(&source).unwrap();

        let target = File::open(&to).unwrap();
        let status = captured.restore(&target);
        let after = Metadata::capture(&target).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(status.starts_with("restored "), "{status}");
        assert_eq!(after.mode, Some(0o751));
        assert_eq!(after.accessed, Some(Time::from_system(accessed)));
        assert_eq!(after.modified, Some(Time::from_system(modified)));
        // Not every filesystem supports user extended attributes.
        if xattrs {
            assert_eq!(after.xattrs, captured.xattrs);
            assert!(status.contains("1 extended attribute"), "{status}");
        }
    }

    #[test]
    fn drops_setuid_without_the_original_owner() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root can give the file away, so there's nothing to drop
        }
        let path = std::env::temp_dir().join(format!("aes256-setuid-{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let file = File::open(&path).unwrap();
        let me = file.metadata().unwrap();
        let meta = Metadata { mode: Some(0o4755), owner: Some((me.uid() + 1, me.gid())), ..Metadata::default() };

        let status = meta.restore(&file);
        let mode = file.metadata().unwrap().mode() & MODE_BITS;
        std::fs::remove_file(&path).unwrap();

        assert_eq!(mode, 0o755);
        assert!(status.contains("owner") && status.contains("permissions 4755 (set to 755)"), "{status}");
    }
}
