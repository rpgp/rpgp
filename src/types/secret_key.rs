use crate::crypto::hash::HashAlgorithm;
use crate::errors::Result;
use crate::types::{EcdsaPublicParams, Mpi, PublicKeyTrait, PublicParams, SecretKeyRepr};

pub trait SecretKeyTrait: PublicKeyTrait {
    type PublicKey;

    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>;

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String;

    fn public_key(&self) -> Self::PublicKey;

    fn public_params(&self) -> &PublicParams;

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

impl<'a, T: SecretKeyTrait> SecretKeyTrait for &'a T {
    type PublicKey = T::PublicKey;

    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        (*self).unlock(pw, work)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        (*self).create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        (*self).public_key()
    }

    fn public_params(&self) -> &PublicParams {
        (*self).public_params()
    }
}
