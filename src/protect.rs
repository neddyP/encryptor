//! Process-wide protections for the keys and plaintext held in memory, and
//! interrupt handling that lets the program clean up before it exits.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// The program's memory allocator: the system's, except that every block is
/// overwritten with zeros when it's freed. Keys and plaintext are wiped where
/// they're used, but this also catches everything else, such as file names,
/// typed answers and the report, so nothing the program held lingers in
/// freed memory. Growing a block goes through `alloc` and `dealloc`, so the
/// old copy is zeroed too.
pub struct ZeroOnFree;

// SAFETY: allocation is passed straight to the system allocator; `dealloc`
// only writes zeros to the block it's given before handing it back.
unsafe impl GlobalAlloc for ZeroOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);
static LOCKING_REQUIRED: AtomicBool = AtomicBool::new(false);
/// Argon2id's working memory was too large to lock, so it was in ordinary
/// memory while a passphrase was made into a key.
static KDF_UNLOCKED: AtomicBool = AtomicBool::new(false);

/// Stack locked below the caller by `lock_stack`: far more than decrypting,
/// encrypting or drawing a screen takes.
const STACK_LOCKED: usize = 256 * 1024;

/// Called first thing in `main`, before any secret exists.
///
/// - Core dumps are disabled. On Linux the process is also marked
///   non-dumpable, which stops other programs running as the same user from
///   reading its memory through ptrace or /proc.
/// - The memory-lock limit is raised as far as the system allows, so more of
///   the plaintext can be kept out of swap.
/// - Ctrl-C, Ctrl-\, SIGTERM and SIGHUP only set a flag. A blocking read then
///   fails with EINTR and the program unwinds normally, wiping keys and
///   plaintext and removing partial files on the way out.
pub fn harden_process() {
    // SAFETY: plain libc calls with valid arguments. The handler only stores
    // to an atomic, which is async-signal-safe.
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);

        let mut memlock: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) == 0 {
            memlock.rlim_cur = memlock.rlim_max;
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &memlock);
        }

        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);

        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Records that the user asked to stop, e.g. Ctrl-C at the hidden key prompt,
/// where the terminal delivers it as a keystroke rather than a signal.
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Fails if the user has asked to stop.
pub fn check() -> Result<()> {
    if stop_requested() { Err(Error::Interrupted) } else { Ok(()) }
}

/// Keeps `len` bytes at `ptr` in RAM so they are never written to swap, and
/// says whether they were locked. Large buffers can exceed the memory-lock
/// limit; that is recorded for the report, and for `check_locked`.
pub fn lock(ptr: *const u8, len: usize) -> bool {
    // SAFETY: the caller passes a live allocation of at least `len` bytes.
    // mlock only pins the pages; it doesn't read or write them.
    if len > 0 && unsafe { libc::mlock(ptr.cast(), len) } != 0 {
        LOCK_FAILED.store(true, Ordering::SeqCst);
        return false;
    }
    true
}

/// Locks `len` bytes at `ptr` in RAM if the limit allows, without counting a
/// failure against the run as `lock` does: for memory that may go unlocked,
/// as Argon2id's may.
pub fn try_lock(ptr: *const u8, len: usize) -> bool {
    // SAFETY: as in `lock`.
    len == 0 || unsafe { libc::mlock(ptr.cast(), len) } == 0
}

/// Records, for the report, that Argon2id's memory couldn't be locked.
pub fn kdf_not_locked() {
    KDF_UNLOCKED.store(true, Ordering::SeqCst);
}

/// Lets go of memory `lock` locked, once it's been wiped, so it doesn't count
/// against the limit while it waits to be reused.
pub fn unlock(ptr: *const u8, len: usize) {
    // SAFETY: as in `lock`; munlock only unpins the pages.
    if len > 0 {
        unsafe { libc::munlock(ptr.cast(), len) };
    }
}

/// Why there's no buffer for a secret.
pub enum NoBuffer {
    /// There isn't this many bytes of memory free.
    Memory(u64),
    /// It couldn't be locked where secrets must be (see `require_locking`).
    Unlocked,
}

/// An empty buffer for secrets with room for exactly `capacity` bytes,
/// allocated up front so it never grows and leaves copies behind, locked in
/// RAM when the limit allows, and wiped when dropped. Fails if there isn't
/// the memory, or if it couldn't be locked where secrets must be.
pub fn locked(capacity: usize) -> std::result::Result<Zeroizing<Vec<u8>>, NoBuffer> {
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(capacity).map_err(|_| NoBuffer::Memory(capacity as u64))?;
    lock(buf.as_ptr(), capacity);
    check_locked().map_err(|_| NoBuffer::Unlocked)?;
    Ok(buf)
}

/// `locked`, filled with `len` zeros.
pub fn locked_zeros(len: usize) -> std::result::Result<Zeroizing<Vec<u8>>, NoBuffer> {
    let mut buf = locked(len)?;
    buf.resize(len, 0);
    Ok(buf)
}

/// From now on, secrets must be kept in locked memory: once anything fails
/// to lock, `check_locked` fails, so the run stops before plaintext goes into
/// memory that could be written to swap. Used by view, which keeps the
/// decrypted file only in locked memory and on the terminal.
pub fn require_locking() {
    LOCKING_REQUIRED.store(true, Ordering::SeqCst);
}

/// Fails if secrets must be kept in locked memory and something couldn't be
/// locked. Called before plaintext is put into memory just locked.
pub fn check_locked() -> Result<()> {
    match LOCKING_REQUIRED.load(Ordering::SeqCst) && LOCK_FAILED.load(Ordering::SeqCst) {
        true => Err(Error::Message(crate::explain::not_locked())),
        false => Ok(()),
    }
}

/// How much more memory this program can lock now, if that's limited: the
/// system's limit on it, less what's locked already, and no more than the
/// memory that's free. `None` where neither can be told.
pub fn lockable() -> Option<u64> {
    let limit = lock_limit().map(|limit| limit.saturating_sub(proc_bytes("/proc/self/status", "VmLck:").unwrap_or(0)));
    // Free memory includes what the system would give up from its caches.
    let free = proc_bytes("/proc/meminfo", "MemAvailable:");
    match (limit, free) {
        (Some(limit), Some(free)) => Some(limit.min(free)),
        (limit, free) => limit.or(free),
    }
}

/// The system's limit on how much memory this program may lock (`ulimit
/// -l`), if it has one. Root isn't held to it.
pub fn lock_limit() -> Option<u64> {
    // SAFETY: geteuid has no arguments and can't fail.
    if unsafe { libc::geteuid() } == 0 {
        return None;
    }
    // SAFETY: rlimit is plain data, filled in by getrlimit.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: reads this process's limit into a valid local.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 || limit.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    // rlim_t is 32 bits on some systems.
    #[allow(clippy::unnecessary_cast)]
    Some(limit.rlim_cur as u64)
}

/// A size in kB from a Linux /proc file, in bytes: the value on the line
/// that starts with `name`.
fn proc_bytes(path: &str, name: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = text.lines().find_map(|line| line.strip_prefix(name))?;
    let kb: u64 = value.trim().strip_suffix("kB")?.trim().parse().ok()?;
    Some(kb * 1024)
}

/// Locks the stack in RAM, from `STACK_LOCKED` bytes below the caller up to
/// its top, so the temporaries that hashing, the cipher and formatting leave
/// on it are never written to swap either. Says whether it was locked.
#[inline(never)]
pub fn lock_stack() -> bool {
    // Written first, so its pages exist to be locked.
    let mut area = [0u8; STACK_LOCKED];
    std::hint::black_box(&mut area);
    let bottom = area.as_ptr() as usize;
    match stack_top() {
        Some(top) if top > bottom => lock(bottom as *const u8, top - bottom),
        _ => {
            LOCK_FAILED.store(true, Ordering::SeqCst);
            false
        }
    }
}

/// The top of this thread's stack, the end it grows down from.
fn stack_top() -> Option<usize> {
    #[cfg(target_os = "linux")]
    // SAFETY: the attributes are filled in by pthread_getattr_np before
    // they're read, and destroyed after.
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
            return None;
        }
        let (mut addr, mut size) = (std::ptr::null_mut(), 0);
        let got = libc::pthread_attr_getstack(&attr, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut attr);
        (got == 0).then(|| addr as usize + size)
    }
    #[cfg(target_os = "macos")]
    // SAFETY: asks about the calling thread, which exists.
    unsafe {
        Some(libc::pthread_get_stackaddr_np(libc::pthread_self()) as usize)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

/// Describes how secrets were held in memory, for the report.
pub fn memory_status() -> &'static str {
    match (LOCK_FAILED.load(Ordering::SeqCst), KDF_UNLOCKED.load(Ordering::SeqCst)) {
        (true, _) => "wiped after use; the file was too large to keep out of swap",
        (false, true) => {
            "kept in RAM (never swapped), wiped after use; the passphrase's Argon2id memory was too large to \
             lock, so it was in ordinary memory, also wiped"
        }
        (false, false) => "kept in RAM (never swapped), wiped after use",
    }
}

/// Overwrites a stretch of the stack below the caller with zeros, so AES key
/// schedules and other temporaries the crypto code left there don't linger.
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u8; 64 * 1024];
    std::hint::black_box(&mut area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_the_stack_down_from_its_top() {
        // Unless the system allows too little to lock even that.
        if lock_limit().is_some_and(|limit| limit < 2 * STACK_LOCKED as u64) {
            return;
        }
        let top = stack_top().expect("the stack's top");
        let here = 0u8;
        assert!(top > std::ptr::addr_of!(here) as usize, "the stack grows down from its top");
        assert!(lock_stack());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn knows_how_much_more_it_can_lock() {
        let free = lockable().expect("Linux says how much memory is free");
        if let Some(limit) = lock_limit() {
            assert!(free <= limit, "{free} free to lock under a limit of {limit}");
        }
        assert!(proc_bytes("/proc/self/status", "VmLck:").is_some());
    }
}
