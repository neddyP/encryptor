//! Version 3 files, encrypted in chunks so that a file of any size is handled
//! in a small, fixed amount of memory, with every chunk authenticated.
//!
//! ```text
//! +--------------+-------------+-----------+---------+---------+-----
//! | magic "AGCM" | version (3) | salt (32) | chunk 0 | chunk 1 | ...
//! +--------------+-------------+-----------+---------+---------+-----
//! ```
//!
//! Each chunk is up to 64 KiB of plaintext encrypted with AES-256-GCM,
//! followed by its 16-byte tag; only the last may be shorter. The plaintext
//! of all the chunks in order is the same as a version 2 file's: the
//! metadata, then the contents.
//!
//! The file's own key is derived from the key and the random salt with
//! HKDF-SHA256, so no two files share one even when the key is reused, and
//! nonces can simply count: chunk n's nonce is n as an 11-byte big-endian
//! number, then 1 for the last chunk or 0 for any other. Every chunk has the
//! header as associated data. Changing, reordering, dropping or adding a
//! chunk, or cutting the file short, makes decryption fail.

use std::io::{self, Read, Write};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::meta::Metadata;
use crate::protect;

pub const VERSION: u8 = 3;
const SALT_START: usize = 5;
pub const HEADER_LEN: usize = SALT_START + 32;
pub const CHUNK: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;
/// The shortest possible file: the header and one chunk holding the 4-byte
/// metadata length.
pub const MIN_LEN: u64 = (HEADER_LEN + 4 + TAG_LEN) as u64;
const KEY_INFO: &[u8] = b"encryptor v3 file key";

pub enum Error {
    Read(io::Error),
    Write(io::Error),
    /// Chunk n failed to authenticate. For the first chunk that can be the
    /// wrong key; for any later one the key is right and the file damaged.
    Auth(u64),
    /// Too short to hold even one complete chunk.
    Truncated,
    Metadata(String),
    Memory(u64),
    Random(getrandom::Error),
    Interrupted,
}

pub struct Encrypted {
    /// SHA-256 of the contents, for verifying the file once written.
    pub hash: Zeroizing<[u8; 32]>,
    pub chunks: u64,
}

pub struct Decrypted {
    pub metadata: Metadata,
    pub len: u64,
    pub hash: Zeroizing<[u8; 32]>,
}

/// Writes a version 3 file to `out`: the header, then `metadata` (already
/// encoded) followed by exactly `len` bytes read from `input`, in chunks.
/// `progress` is told how much of `input` has been read.
pub fn encrypt(
    key: &[u8; 32],
    metadata: &[u8],
    input: &mut impl Read,
    len: u64,
    out: &mut impl Write,
    progress: &mut impl FnMut(u64),
) -> Result<Encrypted, Error> {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(crate::MAGIC);
    header[4] = VERSION;
    getrandom::fill(&mut header[SALT_START..]).map_err(Error::Random)?;
    out.write_all(&header).map_err(Error::Write)?;
    let cipher = file_cipher(key, &header);

    let total = metadata.len() as u64 + len;
    let chunks = total.div_ceil(CHUNK as u64);
    let mut buf = chunk_buffer();
    let mut hasher = Sha256::new();
    let mut metadata = metadata;
    let mut read = 0;
    for n in 0..chunks {
        protect::check().map_err(|_| Error::Interrupted)?;
        let size = (total - n * CHUNK as u64).min(CHUNK as u64) as usize;
        let from_metadata = metadata.len().min(size);
        buf[..from_metadata].copy_from_slice(&metadata[..from_metadata]);
        metadata = &metadata[from_metadata..];
        let contents = &mut buf[from_metadata..size];
        input.read_exact(contents).map_err(Error::Read)?;
        hasher.update(&*contents);
        read += contents.len() as u64;
        progress(read);

        let tag = cipher
            .encrypt_inout_detached(&nonce(n, n + 1 == chunks), &header, (&mut buf[..size]).into())
            .expect("a 64 KiB chunk is well within AES-GCM's limit");
        out.write_all(&buf[..size]).and_then(|()| out.write_all(&tag)).map_err(Error::Write)?;
    }
    Ok(Encrypted { hash: Zeroizing::new(hasher.finalize().into()), chunks })
}

/// Decrypts the chunks of a version 3 file that follow `header`, reading the
/// `body_len` bytes after it from `input` and writing the contents to `out`.
/// `progress` is told how much of the body has been read.
pub fn decrypt(
    key: &[u8; 32],
    header: &[u8; HEADER_LEN],
    input: &mut impl Read,
    body_len: u64,
    out: &mut impl Write,
    progress: &mut impl FnMut(u64),
) -> Result<Decrypted, Error> {
    let full = (CHUNK + TAG_LEN) as u64;
    let chunks = body_len.div_ceil(full);
    let last_len = body_len - chunks.saturating_sub(1) * full;
    if chunks == 0 || last_len <= TAG_LEN as u64 {
        return Err(Error::Truncated);
    }
    let cipher = file_cipher(key, header);

    let mut buf = chunk_buffer();
    let mut unpack = Unpack::new(body_len - chunks * TAG_LEN as u64);
    let mut hasher = Sha256::new();
    let mut len = 0;
    let mut read = 0;
    for n in 0..chunks {
        protect::check().map_err(|_| Error::Interrupted)?;
        let last = n + 1 == chunks;
        let size = if last { last_len } else { full } as usize;
        input.read_exact(&mut buf[..size]).map_err(Error::Read)?;
        read += size as u64;
        progress(read);

        let (data, tag) = buf[..size].split_at_mut(size - TAG_LEN);
        let tag = <&Tag<Aes256Gcm>>::try_from(&*tag).expect("tags are 16 bytes");
        cipher.decrypt_inout_detached(&nonce(n, last), header, data.into(), tag).map_err(|_| Error::Auth(n))?;
        unpack.feed(data, &mut |contents: &[u8]| {
            hasher.update(contents);
            len += contents.len() as u64;
            out.write_all(contents).map_err(Error::Write)
        })?;
    }
    let metadata = unpack.metadata.ok_or_else(|| Error::Metadata(damaged()))?;
    Ok(Decrypted { metadata, len, hash: Zeroizing::new(hasher.finalize().into()) })
}

/// The cipher for one file, under the key derived from `key` and the salt.
fn file_cipher(key: &[u8; 32], header: &[u8; HEADER_LEN]) -> Aes256Gcm {
    let mut file_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&header[SALT_START..]), key)
        .expand(KEY_INFO, &mut file_key[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Aes256Gcm::new((&*file_key).into())
}

fn nonce(n: u64, last: bool) -> Nonce<Aes256Gcm> {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&n.to_be_bytes());
    nonce[11] = last.into();
    nonce.into()
}

/// A buffer for one chunk and its tag, locked in RAM and wiped when dropped.
fn chunk_buffer() -> Zeroizing<Vec<u8>> {
    let buf = Zeroizing::new(vec![0u8; CHUNK + TAG_LEN]);
    protect::lock(buf.as_ptr(), buf.len());
    buf
}

fn damaged() -> String {
    "the metadata stored in the file is damaged".into()
}

/// Separates the decrypted stream, as it arrives, into the metadata at its
/// start and the contents that follow.
struct Unpack {
    /// Plaintext bytes in the whole stream, which the metadata can't exceed.
    total: u64,
    /// The metadata so far, length first. Allocated at its final size once
    /// that is known, so it never grows and leaves copies behind.
    encoded: Zeroizing<Vec<u8>>,
    encoded_len: Option<usize>,
    metadata: Option<Metadata>,
}

impl Unpack {
    fn new(total: u64) -> Self {
        Self { total, encoded: Zeroizing::new(Vec::with_capacity(4)), encoded_len: None, metadata: None }
    }

    fn feed(&mut self, mut data: &[u8], contents: &mut impl FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        while self.metadata.is_none() {
            let wanted = self.encoded_len.unwrap_or(4);
            let take = (wanted - self.encoded.len()).min(data.len());
            self.encoded.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.encoded.len() < wanted {
                return Ok(());
            }
            if self.encoded_len.is_none() {
                let len = 4 + u64::from(u32::from_le_bytes(self.encoded[..4].try_into().expect("4 bytes")));
                if len > self.total {
                    return Err(Error::Metadata(damaged()));
                }
                let mut encoded = Zeroizing::new(Vec::new());
                encoded.try_reserve_exact(len as usize).map_err(|_| Error::Memory(len))?;
                protect::lock(encoded.as_ptr(), len as usize);
                encoded.extend_from_slice(&self.encoded);
                self.encoded = encoded;
                self.encoded_len = Some(len as usize);
            } else {
                self.metadata = Some(Metadata::parse(&self.encoded).map_err(Error::Metadata)?.0);
            }
        }
        if data.is_empty() { Ok(()) } else { contents(data) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn encrypt_bytes(key: &[u8; 32], metadata: &[u8], contents: &[u8]) -> (Vec<u8>, Encrypted) {
        let mut out = Vec::new();
        let sealed = encrypt(key, metadata, &mut &contents[..], contents.len() as u64, &mut out, &mut |_| {})
            .unwrap_or_else(|_| panic!("encryption failed"));
        (out, sealed)
    }

    fn decrypt_bytes(key: &[u8; 32], file: &[u8]) -> Result<(Decrypted, Vec<u8>), Error> {
        let header: [u8; HEADER_LEN] = file[..HEADER_LEN].try_into().unwrap();
        let mut body = &file[HEADER_LEN..];
        let body_len = body.len() as u64;
        let mut out = Vec::new();
        let opened = decrypt(key, &header, &mut body, body_len, &mut out, &mut |_| {})?;
        Ok((opened, out))
    }

    fn auth_failure(result: Result<(Decrypted, Vec<u8>), Error>) -> Option<u64> {
        match result {
            Err(Error::Auth(n)) => Some(n),
            _ => None,
        }
    }

    fn empty_metadata() -> Vec<u8> {
        vec![0; 4]
    }

    #[test]
    fn round_trips_around_chunk_boundaries() {
        for len in [0, 1, CHUNK - 5, CHUNK - 4, CHUNK - 3, CHUNK, 2 * CHUNK - 4, 3 * CHUNK + 17] {
            let contents: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (file, sealed) = encrypt_bytes(&KEY, &empty_metadata(), &contents);
            let chunks = (4 + len).div_ceil(CHUNK) as u64;
            assert_eq!(sealed.chunks, chunks, "len {len}");
            assert_eq!(file.len() as u64, HEADER_LEN as u64 + 4 + len as u64 + chunks * TAG_LEN as u64);

            let (opened, out) = decrypt_bytes(&KEY, &file).unwrap_or_else(|_| panic!("len {len} failed"));
            assert_eq!(out, contents, "len {len}");
            assert_eq!((opened.len, *opened.hash), (len as u64, *sealed.hash));
            assert_eq!(*opened.hash, <[u8; 32]>::from(Sha256::digest(&contents)));
        }
    }

    #[test]
    fn carries_metadata_larger_than_a_chunk() {
        // One extended attribute record bigger than a whole chunk.
        let mut record = b"user.big\0".to_vec();
        record.resize(record.len() + 3 * CHUNK / 2, 0xa5);
        let mut encoded = ((record.len() + 5) as u32).to_le_bytes().to_vec();
        encoded.push(6);
        encoded.extend_from_slice(&(record.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&record);
        let (expected, _) = Metadata::parse(&encoded).unwrap();

        let (file, sealed) = encrypt_bytes(&KEY, &encoded, b"after the metadata");
        assert_eq!(sealed.chunks, 2);
        let (opened, out) = decrypt_bytes(&KEY, &file).unwrap_or_else(|_| panic!("failed"));
        assert_eq!(opened.metadata, expected);
        assert_eq!(out, b"after the metadata");
    }

    #[test]
    fn rejects_the_wrong_key_at_the_first_chunk() {
        let (file, _) = encrypt_bytes(&KEY, &empty_metadata(), &[1; 3 * CHUNK]);
        assert_eq!(auth_failure(decrypt_bytes(&[8; 32], &file)), Some(0));
        // The salt is part of the key, and the header is authenticated.
        for i in [4, SALT_START, HEADER_LEN - 1] {
            let mut changed = file.clone();
            changed[i] ^= 1;
            assert_eq!(auth_failure(decrypt_bytes(&KEY, &changed)), Some(0), "byte {i}");
        }
    }

    #[test]
    fn locates_damage_to_the_chunk() {
        let (file, _) = encrypt_bytes(&KEY, &empty_metadata(), &[2; 4 * CHUNK]);
        let full = CHUNK + TAG_LEN;
        for n in 0..5 {
            for offset in [0, CHUNK / 2, full - 1] {
                let i = HEADER_LEN + n * full + offset;
                if i >= file.len() {
                    continue;
                }
                let mut damaged = file.clone();
                damaged[i] ^= 0x80;
                assert_eq!(auth_failure(decrypt_bytes(&KEY, &damaged)), Some(n as u64), "byte {i}");
            }
        }
    }

    #[test]
    fn notices_chunks_cut_off_added_or_reordered() {
        let (file, _) = encrypt_bytes(&KEY, &empty_metadata(), &[3; 3 * CHUNK]);
        let full = CHUNK + TAG_LEN;

        // Cut at a chunk boundary: the new last chunk wasn't sealed as last.
        let cut = &file[..HEADER_LEN + 2 * full];
        assert_eq!(auth_failure(decrypt_bytes(&KEY, cut)), Some(1));
        // Cut mid-chunk.
        assert!(decrypt_bytes(&KEY, &file[..file.len() - 1]).is_err());
        // A chunk added after the real last one.
        let mut longer = file.clone();
        longer.extend_from_slice(&file[HEADER_LEN..HEADER_LEN + full]);
        assert!(auth_failure(decrypt_bytes(&KEY, &longer)).is_some());
        // Two chunks swapped.
        let mut swapped = file.clone();
        swapped[HEADER_LEN..HEADER_LEN + full].copy_from_slice(&file[HEADER_LEN + full..HEADER_LEN + 2 * full]);
        swapped[HEADER_LEN + full..HEADER_LEN + 2 * full].copy_from_slice(&file[HEADER_LEN..HEADER_LEN + full]);
        assert_eq!(auth_failure(decrypt_bytes(&KEY, &swapped)), Some(0));
        // Nothing after the header at all.
        assert!(matches!(decrypt_bytes(&KEY, &file[..HEADER_LEN]), Err(Error::Truncated)));
    }

    #[test]
    fn gives_every_file_its_own_key() {
        let (a, _) = encrypt_bytes(&KEY, &empty_metadata(), b"same");
        let (b, _) = encrypt_bytes(&KEY, &empty_metadata(), b"same");
        assert_ne!(a[SALT_START..HEADER_LEN], b[SALT_START..HEADER_LEN]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }

    #[test]
    fn reports_progress_through_the_contents() {
        let contents = vec![4; 2 * CHUNK + 100];
        let mut seen = Vec::new();
        let mut out = Vec::new();
        let _ = encrypt(&KEY, &empty_metadata(), &mut &contents[..], contents.len() as u64, &mut out, &mut |done| {
            seen.push(done)
        });
        assert_eq!(seen, [CHUNK as u64 - 4, 2 * CHUNK as u64 - 4, contents.len() as u64]);
    }

    #[test]
    fn decrypts_a_file_made_by_another_implementation() {
        // Made with Python's `cryptography` package: HKDF-SHA256 over key
        // 00 01 .. 1f with salt aa .. aa, then one chunk, sealed as the last,
        // holding empty metadata and "hello".
        let file = hex::decode(KNOWN_FILE).unwrap();
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let (opened, out) = decrypt_bytes(&key, &file).unwrap_or_else(|_| panic!("failed"));
        assert_eq!(out, b"hello");
        assert_eq!(opened.metadata, Metadata::default());
    }

    const KNOWN_FILE: &str = "4147434d03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2163d05168418202b70aeb3d63e4429da7a2a5da78ca6a3b6f";
}
