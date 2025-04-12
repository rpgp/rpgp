use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{bail, ensure, ensure_eq, format_err, Result},
    types::{Ed448PublicParams, SignatureBytes},
};

const MIN_HASH_LEN_BITS: usize = 512;

/// Secret key for EdDSA with Curve448.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    pub secret: cx448::SigningKey,
}

impl From<&SecretKey> for Ed448PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: value.secret.verifying_key(),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(rng: R) -> Self {
        let secret = cx448::SigningKey::generate(rng);

        SecretKey { secret }
    }

    pub(crate) fn try_from_bytes(raw_secret: [u8; 57]) -> Result<Self> {
        let secret = cx448::SigningKey::from(cx448::SecretKey::from_slice(&raw_secret));
        Ok(Self { secret })
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
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
            "EdDSA signature: hash algorithm {:?} is too weak for Ed448",
            hash,
        );
        let signature = self.secret.sign_raw(digest);
        let bytes = signature.to_bytes();
        Ok(SignatureBytes::Native(bytes.to_vec().into()))
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    key: &cx448::VerifyingKey,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    let Some(digest_size) = hash.digest_size() else {
        bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
    };
    ensure!(
        digest_size * 8 >= MIN_HASH_LEN_BITS,
        "EdDSA signature: hash algorithm {:?} is too weak for Ed448",
        hash,
    );
    let sig_bytes = sig_bytes
        .try_into()
        .map_err(|_| format_err!("invalid signature length"))?;
    let sig = cx448::Signature::from_bytes(&sig_bytes)?;

    Ok(key.verify_raw(&sig, hashed)?)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    prop_compose! {
        pub fn key_gen()(bytes: [u8; 57]) -> cx448::SigningKey {
            cx448::SigningKey::from(cx448::SecretKey::from_slice(&bytes))
        }
    }
}
