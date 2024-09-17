use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U12;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, AesGcm, Key as GcmKey, Nonce as GcmNonce, Tag as GcmTag,
};
use eax::{Eax, Key as EaxKey, Nonce as EaxNonce, Tag as EaxTag};
use generic_array::{
    typenum::{U15, U16},
    GenericArray,
};
use num_enum::{FromPrimitive, IntoPrimitive};
use ocb3::{Nonce as Ocb3Nonce, Ocb3, Tag as OcbTag};

use super::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};

type Aes128Ocb3 = Ocb3<Aes128, U15, U16>;
type Aes192Ocb3 = Ocb3<Aes192, U15, U16>;
type Aes256Ocb3 = Ocb3<Aes256, U15, U16>;

/// AES-GCM with a 192-bit key and 96-bit nonce.
pub type Aes192Gcm = AesGcm<Aes192, U12>;

/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
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
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                let tag = GcmTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Gcm)?;
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Eax)?;
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Eax)?;
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                let tag = EaxTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Eax)?;
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                let tag = OcbTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Ocb)?
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                let tag = OcbTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Ocb)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                let tag = OcbTag::from_slice(auth_tag);
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                    .map_err(|_| Error::Ocb)?
            }
            _ => unimplemented_err!("AEAD not supported: {:?}, {:?}", sym_algorithm, self),
        }

        Ok(())
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
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Gcm)?
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Gcm)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Gcm)?
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Eax)?
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Eax)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Eax)?
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Ocb)?
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Ocb)?
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                cipher
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
                    .map_err(|_| Error::Ocb)?
            }
            _ => unimplemented_err!("AEAD not supported: {:?}, {:?}", sym_algorithm, self),
        };

        Ok(tag.to_vec())
    }
}
