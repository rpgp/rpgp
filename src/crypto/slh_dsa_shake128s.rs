use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use slh_dsa::Shake128s;
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure_eq, format_err, Result},
    types::{SignatureBytes, SlhDsaShake128sPublicParams},
};

/// Secret key for SLH DSA Shake128s
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    /// The secret key.
    #[debug("..")]
    pub(crate) key: slh_dsa::SigningKey<Shake128s>,
}

impl Eq for SecretKey {}

impl ZeroizeOnDrop for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // TODO: can we use flat_drop to zeroize?
    }
}

impl From<&SecretKey> for SlhDsaShake128sPublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: value.key.as_ref().clone(),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let key = slh_dsa::SigningKey::new(&mut rng);

        SecretKey { key }
    }

    pub(crate) fn try_from_bytes(seed: [u8; 64]) -> Result<Self> {
        let key = slh_dsa::SigningKey::<Shake128s>::try_from(&seed[..])
            .map_err(|e| format_err!("invalid key {:?}", e))?;
        Ok(Self { key })
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        ensure_eq!(hash, HashAlgorithm::Sha3_256, "invalid hash algorithm");

        let sig = self.key.sign(digest);
        let bytes = sig.to_bytes();

        Ok(SignatureBytes::Native(bytes.to_vec().into()))
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    key: &slh_dsa::VerifyingKey<Shake128s>,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    ensure_eq!(hash, HashAlgorithm::Sha3_256, "invalid hash algorithm");
    ensure_eq!(sig_bytes.len(), 7856, "invalid signature length");

    let sig = slh_dsa::Signature::<Shake128s>::try_from(sig_bytes)?;
    key.verify(hashed, &sig)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    impl Arbitrary for SecretKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u64>()
                .prop_map(|seed| {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed);
                    SecretKey::generate(&mut rng)
                })
                .boxed()
        }
    }
}
