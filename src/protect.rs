//! Process-wide protections for the keys and plaintext held in memory, and
//! interrupt handling that lets the program clean up before it exits.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

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

/// Keeps `len` bytes at `ptr` in RAM so they are never written to swap. Large
/// buffers can exceed the memory-lock limit; that is recorded for the report.
pub fn lock(ptr: *const u8, len: usize) {
    // SAFETY: the caller passes a live allocation of at least `len` bytes.
    // mlock only pins the pages; it doesn't read or write them.
    if len > 0 && unsafe { libc::mlock(ptr.cast(), len) } != 0 {
        LOCK_FAILED.store(true, Ordering::SeqCst);
    }
}

/// Describes how secrets were held in memory, for the report.
pub fn memory_status() -> &'static str {
    if LOCK_FAILED.load(Ordering::SeqCst) {
        "wiped after use; the file was too large to keep out of swap"
    } else {
        "kept in RAM (never swapped), wiped after use"
    }
}

/// Overwrites a stretch of the stack below the caller with zeros, so AES key
/// schedules and other temporaries the crypto code left there don't linger.
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u8; 64 * 1024];
    std::hint::black_box(&mut area);
}
