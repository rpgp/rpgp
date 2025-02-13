use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{
    EcdsaPublicParams, KeyId, KeyVersion, PublicKeyTrait, PublicParams, SignatureBytes,
};

use super::{Fingerprint, KeyDetails};

pub struct Unlocker(Box<dyn FnOnce() -> String>);

impl Unlocker {
    pub fn read(self) -> String {
        self.0()
    }
}

impl<F: FnOnce() -> String + 'static> From<F> for Unlocker {
    fn from(value: F) -> Self {
        Self(Box::new(value))
    }
}

pub trait SigningKey: KeyDetails {
    fn create_signature(
        &self,
        key_pw: Unlocker,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;
}

impl KeyDetails for Box<&dyn SigningKey> {
    fn version(&self) -> KeyVersion {
        (**self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (**self).fingerprint()
    }

    fn key_id(&self) -> KeyId {
        (**self).key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (**self).algorithm()
    }
}

impl SigningKey for Box<&dyn SigningKey> {
    fn create_signature(
        &self,
        key_pw: Unlocker,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (**self).create_signature(key_pw, hash, data)
    }
}

impl<K: SecretKeyTrait> SigningKey for K {
    fn create_signature(
        &self,
        key_pw: Unlocker,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (*self).create_signature(|| key_pw.read(), hash, data)
    }
}

pub trait SecretKeyTrait: KeyDetails + std::fmt::Debug {
    type PublicKey: PublicKeyTrait + Serialize;

    /// The type representing the unlocked version of this.
    type Unlocked;

    /// Unlock the raw data in the secret parameters.
    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PublicParams, &Self::Unlocked) -> Result<T>;

    fn public_key(&self) -> Self::PublicKey;

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>
    where
        F: FnOnce() -> String;

    /// The suggested hash algorithm to calculate the signature hash digest with, when using this
    /// key as a signer
    fn hash_alg(&self) -> HashAlgorithm {
        match self.public_key().public_params() {
            PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => HashAlgorithm::SHA2_384,
            PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => HashAlgorithm::SHA2_512,
            _ => HashAlgorithm::default(),
        }
    }
}

impl<T: SecretKeyTrait> SecretKeyTrait for &T {
    type PublicKey = T::PublicKey;
    type Unlocked = T::Unlocked;

    fn unlock<F, G, S>(&self, pw: F, work: G) -> Result<S>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PublicParams, &Self::Unlocked) -> Result<S>,
    {
        (*self).unlock(pw, work)
    }

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        (*self).create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        (*self).public_key()
    }
}
