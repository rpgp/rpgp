//! # Cryptography module

use self::hash::HashAlgorithm;

pub mod aead;
pub mod aes_kw;
pub mod checksum;
pub mod dsa;
pub mod ecc_curve;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod ed448;
pub mod elgamal;
pub mod hash;
pub mod public_key;
pub mod rsa;
pub mod sym;
pub mod x25519;
pub mod x448;

pub trait Decryptor {
    type EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> crate::errors::Result<Vec<u8>>;
}

pub trait Signer {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> crate::errors::Result<Vec<Vec<u8>>>;
}
