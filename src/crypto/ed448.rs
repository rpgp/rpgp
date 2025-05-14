use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{bail, ensure, ensure_eq, format_err, Result},
    ser::Serialize,
    types::{Ed448PublicParams, SignatureBytes},
};

const MIN_HASH_LEN_BITS: usize = 512;

/// Size in bytes of the ED448 secret key.
pub const KEY_LEN: usize = 57;

/// Secret key for EdDSA with Curve448.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    secret: ed448_goldilocks::SigningKey,
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
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let secret = ed448_goldilocks::SigningKey::generate(rng);

        SecretKey { secret }
    }

    pub fn try_from_bytes(raw: [u8; KEY_LEN]) -> Result<Self> {
        let secret =
            ed448_goldilocks::SigningKey::from(ed448_goldilocks::ScalarBytes::from_slice(&raw));
        Ok(Self { secret })
    }

    /// Returns the secret key in their raw byte level representation.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        let r: &[u8] = self.secret.as_bytes().as_ref();
        r.try_into().expect("known length")
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

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let x = self.as_bytes();
        writer.write_all(x)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        KEY_LEN
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    key: &ed448_goldilocks::VerifyingKey,
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
    let sig = ed448_goldilocks::Signature::from_bytes(&sig_bytes)?;

    Ok(key.verify_raw(&sig, hashed)?)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    prop_compose! {
        pub fn key_gen()(bytes: [u8; 57]) -> ed448_goldilocks::SigningKey {
            ed448_goldilocks::SigningKey::from(ed448_goldilocks::ScalarBytes::from_slice(&bytes))
        }
    }
}
