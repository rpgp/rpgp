//! # Cryptography module

use self::hash::HashAlgorithm;
use crate::types::PublicParams;

pub mod aead;
pub mod aes_kw;
pub mod checksum;
pub mod dsa;
pub mod ecc_curve;
pub mod ecdh;
pub mod ecdsa;
pub mod eddsa;
pub mod hash;
pub mod public_key;
pub mod rsa;
pub mod sym;
pub mod x25519;
pub mod x448;

pub trait Decryptor {
    type Data<'a>;

    fn decrypt(&self, data: Self::Data<'_>) -> crate::errors::Result<Vec<u8>>;
}

pub trait Signer {
    // TODO: make pub_params type safe
    fn sign(
        &self,
        hash: HashAlgorithm,
        digest: &[u8],
        pub_params: &PublicParams,
    ) -> crate::errors::Result<Vec<Vec<u8>>>;
}

pub trait KeyParams {
    type KeyParams;

    fn key_params(&self) -> Self::KeyParams;
}
