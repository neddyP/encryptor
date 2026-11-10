//! Keys from passphrases, with Argon2id. Its working memory is locked in RAM
//! where the system allows that much, and wiped once the key is made. It's
//! usually more than a program may lock (often 8 MiB), and then it's held in
//! ordinary memory for the half second it takes: making it large is what
//! makes each guess at the passphrase expensive on graphics cards.

use argon2::{Algorithm, Argon2, Block, Version};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{self, SecretKey};
use crate::{KEY_LEN, explain, protect};

/// Argon2id's settings. They're stored in each file's header, so new files
/// can be given more without old ones losing their way.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Params {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

/// The settings new files get: 256 MiB, as the age tool's scrypt uses, so a
/// graphics card can only test a few guesses at once, and 3 passes, about
/// half a second on a recent desktop.
pub const DEFAULT: Params = Params { memory_kib: 256 * 1024, passes: 3, lanes: 1 };

/// The most a header may ask for, so a damaged or crafted one can't demand
/// days of work or more memory than any computer has.
const MAX_MEMORY_KIB: u32 = 1 << 20;
const MAX_PASSES: u32 = 1024;
const MAX_LANES: u32 = 16;

/// Bytes the settings take in a header: memory in KiB, passes and lanes, each
/// a little-endian u32.
pub const LEN: usize = 12;

impl Params {
    pub fn to_bytes(self) -> [u8; LEN] {
        let mut bytes = [0u8; LEN];
        bytes[..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.passes.to_le_bytes());
        bytes[8..].copy_from_slice(&self.lanes.to_le_bytes());
        bytes
    }

    /// The settings in `bytes`, if they're ones Argon2id and this version
    /// accept.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let word = |i: usize| bytes.get(i..i + 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")));
        let params = Self { memory_kib: word(0)?, passes: word(4)?, lanes: word(8)? };
        let fits = (1..=MAX_LANES).contains(&params.lanes)
            && (8 * params.lanes..=MAX_MEMORY_KIB).contains(&params.memory_kib)
            && (1..=MAX_PASSES).contains(&params.passes);
        fits.then_some(params)
    }

    /// For the report, such as "Argon2id, 7.0 MiB, 5 passes".
    pub fn summary(self) -> String {
        format!("Argon2id, {}, {} passes", crate::term::short_size(u64::from(self.memory_kib) * 1024), self.passes)
    }
}

/// The key `passphrase` gives for a version 4 file with `header`, with the
/// settings and salt in the header.
pub fn key_for(passphrase: &[u8], header: &[u8]) -> Result<SecretKey> {
    let params = header.get(5..5 + LEN).and_then(Params::from_bytes).ok_or_else(|| {
        Error::KeyOrData(
            "the file's passphrase settings are damaged, or ask for more than this version allows. Try another \
             copy of it, or update encryptor."
                .into(),
        )
    })?;
    derive(passphrase, &params, crate::stream::salt(header))
}

/// The key `passphrase` gives with `params` and `salt`.
pub fn derive(passphrase: &[u8], params: &Params, salt: &[u8]) -> Result<SecretKey> {
    let settings = argon2::Params::new(params.memory_kib, params.passes, params.lanes, Some(KEY_LEN))
        .map_err(|e| Error::KeyOrData(format!("the passphrase's settings in the file are damaged: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, settings);
    let count = argon.params().block_count();
    let bytes = count * Block::SIZE;

    let mut blocks = Zeroizing::new(Vec::new());
    blocks.try_reserve_exact(count).map_err(|_| explain::no_memory(bytes as u64))?;
    blocks.resize(count, Block::new());
    let locked = protect::try_lock(blocks.as_ptr().cast(), bytes);
    if !locked {
        protect::kdf_not_locked();
    }
    let mut key = keys::new_key();
    let hashed = argon.hash_password_into_with_memory(passphrase, salt, &mut key[..], &mut blocks[..]);
    // Wiped while still locked, then let go, so later buffers can be locked.
    blocks.zeroize();
    if locked {
        protect::unlock(blocks.as_ptr().cast(), bytes);
    }
    hashed.map_err(|e| Error::Message(format!("couldn't make a key from the passphrase: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [7; 32];

    #[test]
    fn makes_the_same_key_from_the_same_passphrase_only() {
        let small = Params { memory_kib: 64, passes: 1, lanes: 1 };
        let key = derive(b"correct horse battery staple", &small, &SALT).unwrap();
        assert_eq!(**key, **derive(b"correct horse battery staple", &small, &SALT).unwrap());
        assert_ne!(**key, **derive(b"correct horse battery stapler", &small, &SALT).unwrap());
        assert_ne!(**key, **derive(b"correct horse battery staple", &small, &[8; 32]).unwrap());
        let more = Params { passes: 2, ..small };
        assert_ne!(**key, **derive(b"correct horse battery staple", &more, &SALT).unwrap());
    }

    #[test]
    fn matches_the_reference_argon2id() {
        // Made with Python's `cryptography` package: Argon2id version 19,
        // 32 KiB, 3 passes, 4 lanes, a password of 32 bytes of 1 and a salt
        // of 16 bytes of 2.
        let params = Params { memory_kib: 32, passes: 3, lanes: 4 };
        let key = derive(&[1; 32], &params, &[2; 16]).unwrap();
        assert_eq!(hex::encode(**key), "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e");
    }

    #[test]
    fn reads_back_what_it_writes_and_refuses_the_absurd() {
        assert_eq!(Params::from_bytes(&DEFAULT.to_bytes()), Some(DEFAULT));
        let absurd = Params { memory_kib: u32::MAX, ..DEFAULT };
        assert_eq!(Params::from_bytes(&absurd.to_bytes()), None);
        assert_eq!(Params::from_bytes(&Params { passes: 0, ..DEFAULT }.to_bytes()), None);
        assert_eq!(Params::from_bytes(&Params { lanes: 0, ..DEFAULT }.to_bytes()), None);
        assert_eq!(Params::from_bytes(&DEFAULT.to_bytes()[..8]), None);
        assert_eq!(DEFAULT.summary(), "Argon2id, 256.0 MiB, 3 passes");
        assert_eq!(Params::from_bytes(&DEFAULT.to_bytes()).map(|p| p.memory_kib), Some(256 * 1024));
    }
}
