//! An abstraction to provide a signer that is compatible with rPGP, but backed by a Rust Crypto
//! [`signature::Signer`].
//!
//! This allows use of keys in HSMs or other secure controllers.

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
