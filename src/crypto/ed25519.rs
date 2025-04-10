//! EdDSA for OpenPGP.
//!
//! OpenPGP RFC 9580 specifies use of Ed25519 and Ed448.
//!
//! Use of Ed25519 is defined with two different framings (using different key types) in RFC 9580:
//! - The new key format is called `Ed25519`. It can be used both with v4 and v6 keys.
//! - The old key format has been renamed `EdDSALegacy`. It may only be used with v4 keys.
//!
//! Note: The two variants `Ed25519` and `EdDSALegacy` use the same cryptographic mechanism,
//! and are interchangeable in terms of the low-level cryptographic primitives.
//! However, at the OpenPGP layer their representation in the key material differs.
//! This implicitly yields differing OpenPGP fingerprints, so the two OpenPGP key variants cannot
//! be used interchangeably.

use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{bail, ensure, ensure_eq, Result},
    types::{Ed25519PublicParams, EddsaLegacyPublicParams, Mpi},
};

const MIN_HASH_LEN_BITS: usize = 256;

/// Specifies which OpenPGP framing (e.g. `Ed25519` vs. `EdDSALegacy`) is used, and also chooses
/// between curve Ed25519 and Ed448 (TODO: not yet implemented)
pub enum Mode {
    /// EdDSALegacy (with curve Ed25519). May only be used with v4 keys.
    ///
    /// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#key-eddsa-legacy>
    EdDSALegacy,

    /// Ed25519 as defined in RFC 9580
    ///
    /// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2>
    Ed25519,
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    pub secret: ed25519_dalek::SigningKey,
}

impl From<&SecretKey> for Ed25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: value.secret.verifying_key(),
        }
    }
}

impl From<&SecretKey> for EddsaLegacyPublicParams {
    fn from(value: &SecretKey) -> Self {
        Self::Ed25519 {
            key: value.secret.verifying_key(),
        }
    }
}

impl SecretKey {
    /// Generate an EdDSA `SecretKey`.
    ///
    /// This SecretKey type can be used to form either a `EddsaLegacyPublicParams` or a
    /// `Ed25519PublicParams`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let mut bytes = Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
        rng.fill_bytes(&mut *bytes);
        let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);

        SecretKey { secret }
    }

    pub(crate) fn try_from_bytes(raw_secret: [u8; 32]) -> Result<Self> {
        let secret = ed25519_dalek::SigningKey::from(raw_secret);
        Ok(Self { secret })
    }

    pub(crate) fn as_mpi(&self) -> Mpi {
        Mpi::from_slice(&self.secret.to_bytes())
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
        let Some(digest_size) = hash.digest_size() else {
            bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
        };
        ensure_eq!(
            digest.len(),
            digest_size,
            "Unexpected digest length {} for hash algorithm {:?}",
            digest.len(),
            hash,
        );
        ensure!(
            digest_size * 8 >= MIN_HASH_LEN_BITS,
            "EdDSA signature: hash algorithm {:?} is too weak for Ed25519",
            hash,
        );

        let signature = self.secret.sign(digest);
        let bytes = signature.to_bytes();

        let r = bytes[..32].to_vec();
        let s = bytes[32..].to_vec();

        Ok(vec![r, s])
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    key: &ed25519_dalek::VerifyingKey,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    let Some(digest_size) = hash.digest_size() else {
        bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
    };
    ensure!(
        digest_size * 8 >= MIN_HASH_LEN_BITS,
        "EdDSA signature: hash algorithm {:?} is too weak for Ed25519",
        hash,
    );

    let sig = sig_bytes.try_into()?;

    Ok(key.verify(hashed, &sig)?)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    prop_compose! {
        pub fn key_gen()(bytes: [u8; 32]) -> ed25519_dalek::SigningKey {
            ed25519_dalek::SigningKey::from_bytes(&bytes)
        }
    }
}
