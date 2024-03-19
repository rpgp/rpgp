//! # Cryptography module

use crate::types::Mpi;

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

pub trait Decryptor {
    fn decrypt(&self, mpis: &[Mpi], fingerprint: &[u8]) -> crate::errors::Result<Vec<u8>>;
}

pub trait KeyParams {
    type KeyParams;

    fn key_params(&self) -> Self::KeyParams;
}
