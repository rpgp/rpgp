use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, AeadInOut, KeyInit},
    Aes128Gcm, Aes256Gcm, AesGcm, Key as GcmKey, Nonce as GcmNonce,
};
use bytes::BytesMut;
use cipher::{
    array::Array,
    typenum::{U15, U16},
};
use eax::{Eax, Key as EaxKey, Nonce as EaxNonce};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use ocb3::{Nonce as Ocb3Nonce, Ocb3};
use sha2::Sha256;
use snafu::Snafu;
use zeroize::Zeroizing;

use super::sym::SymmetricKeyAlgorithm;
use crate::types::Tag;

type Aes128Ocb3 = Ocb3<Aes128, U15, U16>;
type Aes192Ocb3 = Ocb3<Aes192, U15, U16>;
type Aes256Ocb3 = Ocb3<Aes256, U15, U16>;

/// AES-GCM with a 192-bit key and 96-bit nonce.
pub type Aes192Gcm = AesGcm<Aes192, U12>;

mod decryptor;
mod encryptor;

pub use self::{decryptor::StreamDecryptor, encryptor::StreamEncryptor};

/// AEAD related possible errors.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("unsupported algorithm {:?}", alg))]
    UnsupporedAlgorithm { alg: AeadAlgorithm },
    #[snafu(display("invalid session key: length does not match {} != {}", alg.key_size(), session_key_size))]
    InvalidSessionKey {
        alg: SymmetricKeyAlgorithm,
        session_key_size: usize,
    },
    #[snafu(display("decryption failed: {:?}", alg))]
    Decrypt { alg: AeadAlgorithm },
    #[snafu(display("encryption failed: {:?}", alg))]
    Encrypt { alg: AeadAlgorithm },
}

/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// None
    None = 0,
    Eax = 1,
    Ocb = 2,
    Gcm = 3,

    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Other(#[cfg_attr(test, proptest(strategy = "110u8.."))] u8),
}

impl AeadAlgorithm {
    /// Nonce size used for this AEAD algorithm.
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Eax => 16,
            Self::Ocb => 15,
            Self::Gcm => 12,
            _ => 0,
        }
    }

    /// Size of the IV.
    pub fn iv_size(&self) -> usize {
        match self {
            Self::Eax => 16,
            Self::Ocb => 15,
            Self::Gcm => 12,
            _ => 0,
        }
    }

    /// Size of the authentication tag.
    pub fn tag_size(&self) -> Option<usize> {
        match self {
            Self::Eax => Some(16),
            Self::Ocb => Some(16),
            Self::Gcm => Some(16),
            _ => None,
        }
    }

    /// Decrypt the provided data in place.
    pub fn decrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut BytesMut,
    ) -> Result<(), Error> {
        let res = match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            _ => {
                return Err(UnsupporedAlgorithmSnafu { alg: *self }.build());
            }
        };
        res.map_err(|_| DecryptSnafu { alg: *self }.build())
    }

    /// Encrypt the provided data in place.
    pub fn encrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut BytesMut,
    ) -> Result<(), Error> {
        let res = match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = Array::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            _ => {
                return Err(UnsupporedAlgorithmSnafu { alg: *self }.build());
            }
        };

        res.map_err(|_| EncryptSnafu { alg: *self }.build())
    }
}

/// Get (info, message_key, nonce) for the given parameters
#[allow(clippy::type_complexity)]
pub(crate) fn aead_setup_rfc9580(
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    salt: &[u8],
    ikm: &[u8],
) -> ([u8; 5], Zeroizing<Vec<u8>>, Vec<u8>) {
    let info = [
        Tag::SymEncryptedProtectedData.encode(), // packet type
        0x02,                                    // version
        sym_alg.into(),
        aead.into(),
        chunk_size.into(),
    ];

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 42]);
    hk.expand(&info, okm.as_mut_slice()).expect("42");

    let mut message_key = Zeroizing::new(vec![0; sym_alg.key_size()]);
    message_key.copy_from_slice(&okm.as_slice()[..sym_alg.key_size()]);

    let raw_iv_len = aead.nonce_size() - 8;
    let iv = &okm[sym_alg.key_size()..sym_alg.key_size() + raw_iv_len];
    let mut nonce = vec![0u8; aead.nonce_size()];
    nonce[..raw_iv_len].copy_from_slice(iv);

    (info, message_key, nonce)
}

/// Allowed chunk sizes.
/// The range is from 64B to 4 MiB.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-version-2-symmetrically-enc>
#[derive(
    Default, IntoPrimitive, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, TryFromPrimitive,
)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ChunkSize {
    C64B = 0,
    C128B = 1,
    C256B = 2,
    C512B = 3,
    C1KiB = 4,
    C2KiB = 5,
    #[default]
    C4KiB = 6,
    C8KiB = 7,
    C16KiB = 8,
    C32KiB = 9,
    C64KiB = 10,
    C128KiB = 11,
    C256KiB = 12,
    C512KiB = 13,
    C1MiB = 14,
    C2MiB = 15,
    C4MiB = 16,
}

impl ChunkSize {
    /// Returns the number of bytes for this chunk size.
    pub const fn as_byte_size(self) -> u32 {
        1u32 << ((self as u32) + 6)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use log::info;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_chunk_size() {
        assert_eq!(ChunkSize::default().as_byte_size(), 4 * 1024);
        assert_eq!(ChunkSize::C64B.as_byte_size(), 64);
    }
    macro_rules! roundtrip {
        ($name:ident, $sym_alg:path, $aead:path) => {
            #[test]
            fn $name() {
                pretty_env_logger::try_init().ok();

                let mut data_rng = ChaCha8Rng::seed_from_u64(0);

                const MAX_SIZE: usize = 2048;

                // Protected
                for i in 1..MAX_SIZE {
                    info!("Size {}", i);
                    let mut data = vec![0u8; i];
                    data_rng.fill(&mut data[..]);

                    let mut key = vec![0u8; $sym_alg.key_size()];
                    data_rng.fill(&mut key[..]);

                    let mut salt = [0u8; 32];
                    data_rng.fill(&mut salt[..]);

                    info!("encrypt");
                    let mut ciphertext = Vec::new();

                    {
                        info!("encrypt streaming");
                        let mut input = std::io::Cursor::new(&data);

                        let mut encryptor = StreamEncryptor::new(
                            $sym_alg,
                            $aead,
                            ChunkSize::default(),
                            &key,
                            &salt,
                            &mut input,
                        )
                        .unwrap();
                        encryptor.read_to_end(&mut ciphertext).unwrap();
                    }

                    {
                        info!("decrypt streaming");
                        let mut decryptor = StreamDecryptor::new_rfc9580(
                            $sym_alg,
                            $aead,
                            ChunkSize::default(),
                            &salt,
                            &key,
                            &ciphertext[..],
                        )
                        .unwrap();

                        let mut plaintext = Vec::new();
                        decryptor.read_to_end(&mut plaintext).unwrap();
                        assert_eq!(
                            hex::encode(&data),
                            hex::encode(&plaintext),
                            "stream decrypt failed"
                        );
                    }
                }
            }
        };
    }

    roundtrip!(
        roundtrip_aead_eax_aes128_gcm,
        SymmetricKeyAlgorithm::AES128,
        AeadAlgorithm::Gcm
    );
    roundtrip!(
        roundtrip_aead_eax_aes192_gcm,
        SymmetricKeyAlgorithm::AES192,
        AeadAlgorithm::Gcm
    );
    roundtrip!(
        roundtrip_aead_eax_aes256_gcm,
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Gcm
    );

    roundtrip!(
        roundtrip_aead_eax_aes128_eax,
        SymmetricKeyAlgorithm::AES128,
        AeadAlgorithm::Eax
    );
    roundtrip!(
        roundtrip_aead_eax_aes192_eax,
        SymmetricKeyAlgorithm::AES192,
        AeadAlgorithm::Eax
    );
    roundtrip!(
        roundtrip_aead_eax_aes256_eax,
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Eax
    );
    roundtrip!(
        roundtrip_aead_eax_aes128_ocb,
        SymmetricKeyAlgorithm::AES128,
        AeadAlgorithm::Ocb
    );
    roundtrip!(
        roundtrip_aead_eax_aes192_ocb,
        SymmetricKeyAlgorithm::AES192,
        AeadAlgorithm::Ocb
    );
    roundtrip!(
        roundtrip_aead_eax_aes256_ocb,
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb
    );
}
