use ml_dsa::{KeyGen, MlDsa87};
use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, Result},
    types::{MlDsa87Ed448PublicParams, SignatureBytes},
};

/// Secret key for ML DSA 87 with Curve448.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    pub ed448: cx448::SigningKey,
    #[debug("..")]
    pub ml_dsa_sign: Box<ml_dsa::SigningKey<MlDsa87>>,
    #[debug("{}", hex::encode(ml_dsa_verify.encode()))]
    pub ml_dsa_verify: Box<ml_dsa::VerifyingKey<MlDsa87>>,
    // Store the seed, as it can't be extracted from the ml_dsa keys currently
    #[debug("..")]
    pub ml_dsa_seed: [u8; 32],
}

impl Eq for SecretKey {}

impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlDsa87Ed448PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            ed448: value.ed448.verifying_key(),
            ml_dsa: value.ml_dsa_verify.clone(),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let ed448 = cx448::SigningKey::generate(&mut rng);
        let mut ml_dsa_seed = [0u8; 32];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = MlDsa87::key_gen_internal(&ml_dsa_seed.into());

        SecretKey {
            ed448,
            ml_dsa_sign: Box::new(ml_dsa.signing_key().clone()),
            ml_dsa_verify: Box::new(ml_dsa.verifying_key().clone()),
            ml_dsa_seed,
        }
    }

    pub(crate) fn try_from_bytes(raw_ed448: [u8; 57], ml_dsa_seed: [u8; 32]) -> Result<Self> {
        let ed448 = cx448::SigningKey::from(cx448::SecretKey::from_slice(&raw_ed448));
        // use the seed format
        let keypair = MlDsa87::key_gen_internal(&ml_dsa_seed.into());

        Ok(Self {
            ed448,
            ml_dsa_sign: Box::new(keypair.signing_key().clone()),
            ml_dsa_verify: Box::new(keypair.verifying_key().clone()),
            ml_dsa_seed,
        })
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        ensure!(
            ![
                HashAlgorithm::Md5,
                HashAlgorithm::Ripemd160,
                HashAlgorithm::Sha1
            ]
            .contains(&hash),
            "invalid hash algorithm"
        );

        let ed448_sig = self.ed448.sign(digest);
        let mut bytes = ed448_sig.to_bytes().to_vec();
        let ml_dsa_sig = self.ml_dsa_sign.sign(digest);
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    ed_key: &cx448::VerifyingKey,
    ml_dsa_key: &ml_dsa::VerifyingKey<MlDsa87>,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    ensure!(
        ![
            HashAlgorithm::Md5,
            HashAlgorithm::Ripemd160,
            HashAlgorithm::Sha1
        ]
        .contains(&hash),
        "invalid hash algorithm"
    );
    ensure_eq!(sig_bytes.len(), 114 + 4627, "invalid signature length");

    let ed_sig = cx448::Signature::try_from(&sig_bytes[..114])?;
    ed_key.verify(hashed, &ed_sig)?;

    let ml_sig = sig_bytes[114..].try_into()?;
    ml_dsa_key.verify(hashed, &ml_sig)?;

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
