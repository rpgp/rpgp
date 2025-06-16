//! This module provides an abstraction to provide a signer compatible with
//! [`pgp`] but backed by a [`signature::Signer`] to keep keys in HSMs or other
//! secure controllers.

mod ecdsa;
mod rsa;

pub use self::{
    ecdsa::{EcdsaSigner, PgpEcdsaPublicKey},
    rsa::RsaSigner,
};
use crate::{crypto::public_key::PublicKeyAlgorithm, types::PublicParams};

/// Public key PGP parameters for a given public key
pub trait PublicKey {
    /// Algorithm ID for a given signing algorithm
    const PGP_ALGORITHM: PublicKeyAlgorithm;

    /// Public key encoding for a public key
    fn pgp_parameters(&self) -> PublicParams;
}
