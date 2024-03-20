use aes::{Aes128, Aes256};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Key as GcmKey, Nonce as GcmNonce, Tag as GcmTag,
};
use eax::{Eax, Key as EaxKey, Nonce as EaxNonce, Tag as EaxTag};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::errors::{Error, Result};

use super::sym::SymmetricKeyAlgorithm;

/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
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
    Other(u8),
}

impl Default for AeadAlgorithm {
    fn default() -> Self {
        AeadAlgorithm::None
    }
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
    pub fn tag_size(&self) -> usize {
        match self {
            Self::Eax => 16,
            Self::Ocb => 16,
            Self::Gcm => 16,
            _ => 0,
        }
    }

    /// Decrypt the provided data in place.
    pub fn decrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        auth_tag: &[u8],
        buffer: &mut [u8],
    ) -> Result<()> {
        match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, buffer, &tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, buffer, &tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, buffer, &tag)
                    .map_err(|_| Error::Eax)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, buffer, &tag)
                    .map_err(|_| Error::Eax)?;
            }
            _ => unimplemented_err!("AEAD not supported: {:?}, {:?}", sym_algorithm, self),
        }

        Ok(())
    }

    /// Decrypt the provided data.
    pub fn decrypt(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        auth_tag: &[u8],
        buffer: &[u8],
    ) -> Result<Vec<u8>> {
        let mut out = buffer.to_vec();
        match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, &mut out, &tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, &mut out, &tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, &mut out, &tag)
                    .map_err(|_| Error::Eax)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(&nonce, associated_data, &mut out, &tag)
                    .map_err(|_| Error::Eax)?;
            }
            _ => unimplemented_err!("AEAD not supported: {:?}, {:?}", sym_algorithm, self),
        }

        Ok(out)
    }

    /// Encrypt the provided data in place.
    pub fn encrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Vec<u8>> {
        let tag = match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(&nonce, associated_data, buffer)
                    .map_err(|_| Error::Gcm)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(&key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(&nonce, associated_data, buffer)
                    .map_err(|_| Error::Gcm)?
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(&nonce, associated_data, buffer)
                    .map_err(|_| Error::Eax)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(&key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(&nonce, associated_data, buffer)
                    .map_err(|_| Error::Eax)?
            }
            _ => unimplemented_err!("AEAD not supported: {:?}, {:?}", sym_algorithm, self),
        };

        Ok(tag.to_vec())
    }
}
