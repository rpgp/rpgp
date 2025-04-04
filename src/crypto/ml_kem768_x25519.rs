use std::cmp::PartialEq;

use log::debug;
use ml_kem::kem::DecapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use rand::{CryptoRng, Rng};
use x25519_dalek::PublicKey;
use zeroize::ZeroizeOnDrop;

use crate::{crypto::Decryptor, errors::Result, types::MlKem768X25519PublicParams};

use super::x25519;

/// Secret key for X25519
#[derive(Clone, derive_more::Debug, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) x25519: super::x25519::SecretKey,
    #[debug("..")]
    pub(crate) ml_kem: DecapsulationKey<MlKem768Params>,
}

impl From<&SecretKey> for MlKem768X25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            x25519_key: PublicKey::from(&value.x25519.secret),
            ml_kem_key: value.ml_kem.encapsulation_key(),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.x25519.eq(&other.x25519) && self.ml_kem.eq(&other.ml_kem)
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    /// Generate a `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        todo!()
    }

    pub(crate) fn try_from_parts(x: x25519::SecretKey, ml_kem: [u8; 64]) -> Result<Self> {
        let ml_kem = DecapsulationKey::from_bytes(&(ml_kem.into()));

        Ok(Self { x25519: x, ml_kem })
    }
}

pub struct EncryptionFields<'a> {
    /// Ephemeral X25519 public key (32 bytes)
    pub ephemeral_public_point: [u8; 32],

    /// Recipient public key (32 bytes)
    pub recipient_public: [u8; 32],

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        debug!("ML KEM 768 X25519 decrypt");

        todo!()
    }
}
