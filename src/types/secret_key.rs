use zeroize::Zeroizing;

use super::{Fingerprint, KeyDetails};
use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    types::{KeyId, KeyVersion},
};

/// Wraps around a callback to unlock keys.
#[derive(derive_more::Debug)]
pub enum Password {
    Dynamic(#[debug("Box<Fn>")] Box<dyn Fn() -> Zeroizing<Vec<u8>>>),
    Static(#[debug("***")] Zeroizing<Vec<u8>>),
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&[u8]> for Password {
    fn from(value: &[u8]) -> Self {
        Self::Static(value.to_vec().into())
    }
}

impl Default for Password {
    fn default() -> Self {
        Self::empty()
    }
}

impl Password {
    /// Creates an empty password unlocker.
    pub fn empty() -> Self {
        Self::Static(Vec::new().into())
    }

    /// Executes the callback and returns the result.
    pub fn read(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Dynamic(ref f) => f(),
            Self::Static(ref s) => s.clone(),
        }
    }
}

impl<F: Fn() -> Zeroizing<Vec<u8>> + 'static> From<F> for Password {
    fn from(value: F) -> Self {
        Self::Dynamic(Box::new(value))
    }
}

impl KeyDetails for Box<&dyn SecretKeyTrait> {
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

impl SecretKeyTrait for Box<&dyn SecretKeyTrait> {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (**self).create_signature(key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        (**self).hash_alg()
    }
}

pub trait SecretKeyTrait: KeyDetails + std::fmt::Debug {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;

    /// The recommended hash algorithm to calculate the signature hash digest with,
    /// when using this as a signer
    fn hash_alg(&self) -> HashAlgorithm;
}
