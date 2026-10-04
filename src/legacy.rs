//! Format versions 1 and 2, which encrypted the whole file in one piece and
//! are still decrypted, though no longer written.
//!
//! ```text
//! +--------------+-------------+------------+----------------+----------+
//! | magic "AGCM" | version     | nonce (12) | ciphertext (n) | tag (16) |
//! +--------------+-------------+------------+----------------+----------+
//! ```
//!
//! The 17-byte header is passed to GCM as associated data, so changing any
//! byte of the header, ciphertext or tag makes decryption fail. Version 2's
//! plaintext starts with the original file's metadata (see `meta`); version
//! 1's is just the contents.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::error::{Error, Result};
use crate::meta::Metadata;

const NONCE_START: usize = crate::MAGIC.len() + 1;
const HEADER_LEN: usize = NONCE_START + 12;
const TAG_LEN: usize = 16;
/// The shortest possible file: a header and a tag around nothing.
pub const MIN_LEN: u64 = (HEADER_LEN + TAG_LEN) as u64;

/// Authenticates and decrypts a whole version 1 or 2 file image in place and
/// returns the stored metadata, if the version has any, and the contents.
/// Fails with `AuthFailed` if the key is wrong or any byte of the header,
/// ciphertext or tag has changed.
pub fn decrypt(key: &[u8; KEY_LEN], mut blob: Zeroizing<Vec<u8>>) -> Result<(Option<Metadata>, Zeroizing<Vec<u8>>)> {
    if blob.len() < MIN_LEN as usize {
        return Err("the file is too short to be an encrypted file".into());
    }
    let version = blob[NONCE_START - 1];
    if !matches!(version, 1 | 2) {
        return Err(format!("format version {version} isn't encrypted whole").into());
    }

    let body_len = blob.len() - HEADER_LEN - TAG_LEN;
    let (header, rest) = blob.split_at_mut(HEADER_LEN);
    let (body, tag) = rest.split_at_mut(body_len);
    let header = &*header;
    let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).expect("nonce is 12 bytes");
    let tag = <&Tag<Aes256Gcm>>::try_from(&*tag).expect("tag is 16 bytes");
    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(nonce, header, body.into(), tag)
        .map_err(|_| Error::AuthFailed)?;

    let (metadata, skip) = match version {
        1 => (None, 0),
        _ => {
            let (metadata, len) = Metadata::parse(&blob[HEADER_LEN..HEADER_LEN + body_len])?;
            (Some(metadata), len)
        }
    };
    blob.copy_within(HEADER_LEN + skip..HEADER_LEN + body_len, 0);
    blob.truncate(body_len - skip);
    Ok((metadata, blob))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use super::*;

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    /// A whole-file image as `version` wrote it, with `plain` as its plaintext.
    fn encrypt(key: &[u8; KEY_LEN], version: u8, plain: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut header = [0u8; HEADER_LEN];
        header[..NONCE_START - 1].copy_from_slice(crate::MAGIC);
        header[NONCE_START - 1] = version;
        getrandom::fill(&mut header[NONCE_START..]).unwrap();
        let mut data = plain.to_vec();
        let nonce = <&Nonce<Aes256Gcm>>::try_from(&header[NONCE_START..]).unwrap();
        let tag = Aes256Gcm::new(key.into()).encrypt_inout_detached(nonce, &header, data.as_mut_slice().into()).unwrap();
        Zeroizing::new([&header[..], &data, &tag[..]].concat())
    }

    /// A version 2 image of `contents` with `metadata` in front.
    fn version_2(key: &[u8; KEY_LEN], metadata: &Metadata, contents: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut plain = vec![0; metadata.encoded_len()];
        metadata.encode(&mut plain);
        plain.extend_from_slice(contents);
        encrypt(key, 2, &plain)
    }

    fn decrypted(key: &[u8; KEY_LEN], blob: Zeroizing<Vec<u8>>) -> Option<(Option<Metadata>, Vec<u8>)> {
        decrypt(key, blob).ok().map(|(metadata, plain)| (metadata, plain.to_vec()))
    }

    #[test]
    fn round_trips_all_sizes() {
        let k = key(7);
        for len in [0, 1, 15, 16, 17, 4096, 100_003] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = version_2(&k, &Metadata::default(), &plain);
            assert_eq!(blob.len(), HEADER_LEN + 4 + len + TAG_LEN);
            assert_eq!(decrypted(&k, blob), Some((Some(Metadata::default()), plain)));
        }
    }

    #[test]
    fn carries_metadata_inside_the_encryption() {
        let path = std::env::temp_dir().join(format!("encryptor-carry-{}", std::process::id()));
        fs::write(&path, b"contents").unwrap();
        let metadata = Metadata::capture(&File::open(&path).unwrap()).unwrap();
        fs::remove_file(&path).unwrap();

        let blob = version_2(&key(8), &metadata, b"contents");
        assert!(!blob.windows(8).any(|w| w == b"contents"), "contents visible");
        assert_eq!(decrypted(&key(8), blob), Some((Some(metadata), b"contents".to_vec())));
    }

    #[test]
    fn opens_version_1_files_without_metadata() {
        let blob = encrypt(&key(9), 1, b"made by 0.1");
        assert_eq!(decrypted(&key(9), blob), Some((None, b"made by 0.1".to_vec())));
    }

    #[test]
    fn rejects_wrong_key() {
        let blob = version_2(&key(1), &Metadata::default(), b"secret");
        assert!(matches!(decrypt(&key(2), blob), Err(Error::AuthFailed)));
    }

    #[test]
    fn rejects_any_modified_byte() {
        let blob = version_2(&key(3), &Metadata::default(), b"thirty-two bytes of plaintext!!!");
        for i in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[i] ^= 0x01;
            assert!(decrypt(&key(3), tampered).is_err(), "byte {i} change went unnoticed");
        }
    }

    #[test]
    fn rejects_truncated_file() {
        let blob = version_2(&key(4), &Metadata::default(), b"hello");
        let short = Zeroizing::new(blob[..blob.len() - 1].to_vec());
        assert!(decrypt(&key(4), short).is_err());
    }
}
