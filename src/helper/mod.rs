//! This module provides an abstraction to provide a signer compatible with
//! [`pgp`] but backed by a [`signature::Signer`] to keep keys in HSMs or other
//! secure controllers.

mod ecdsa;
mod rsa;

pub use self::{
    ecdsa::{EcdsaSigner, PgpEcdsaPublicKey},
    rsa::RsaSigner,
};

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    types::PublicParams,
};

/// Public key PGP parameters for a given public key
pub trait PgpPublicKey {
    /// Algorithm ID for a given signing algorithm
    const PGP_ALGORITHM: PublicKeyAlgorithm;

    /// Public key encoding for a public key
    fn pgp_parameters(&self) -> PublicParams;
}

/// Equivalent PGP hash algorithm for a given digest
pub trait PgpHash {
    /// PGP Algorithm ID for a given digest
    const HASH_ALGORITHM: HashAlgorithm;
}

impl PgpHash for sha1::Sha1 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA1;
}

impl PgpHash for sha2::Sha256 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA2_256;
}

impl PgpHash for sha2::Sha384 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA2_384;
}

impl PgpHash for sha2::Sha512 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA2_512;
}
