use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::types::{
    EcdsaPublicParams, KeyId, KeyVersion, PublicKeyTrait, PublicParams, SignatureBytes,
};

use super::Fingerprint;

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

pub trait SigningKey {
    fn version(&self) -> KeyVersion;
    fn fingerprint(&self) -> Fingerprint;
    fn key_id(&self) -> KeyId;
    fn algorithm(&self) -> PublicKeyAlgorithm;

    fn create_signature(
        &self,
        key_pw: Unlocker,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;
}

impl SigningKey for Box<&dyn SigningKey> {
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
    fn version(&self) -> KeyVersion {
        PublicKeyTrait::version(self)
    }

    fn fingerprint(&self) -> Fingerprint {
        PublicKeyTrait::fingerprint(self)
    }

    fn key_id(&self) -> KeyId {
        PublicKeyTrait::key_id(self)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyTrait::algorithm(self)
    }

    fn create_signature(
        &self,
        key_pw: Unlocker,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        SecretKeyTrait::create_signature(self, || key_pw.read(), hash, data)
    }
}

pub trait SecretKeyTrait: PublicKeyTrait {
    type PublicKey;

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
        match self.public_params() {
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
