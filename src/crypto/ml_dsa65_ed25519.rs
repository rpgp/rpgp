use ml_dsa::{KeyGen, MlDsa65};
use rand::{CryptoRng, RngCore};
use signature::{Signer as _, Verifier};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, Result},
    ser::Serialize,
    types::{MlDsa65Ed25519PublicParams, SignatureBytes},
};

/// Size in bytes of the ED25519 secret key.
pub const ED25519_KEY_LEN: usize = 32;
/// Size in bytes of the ML DSA 65 secret key.
pub const ML_DSA65_KEY_LEN: usize = 32;

/// Secret key for ML DSA 65 with Curve25519.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    ed25519: ed25519_dalek::SigningKey,
    #[debug("..")]
    ml_dsa_sign: Box<ml_dsa::SigningKey<MlDsa65>>,
    #[debug("{}", hex::encode(ml_dsa_verify.encode()))]
    ml_dsa_verify: Box<ml_dsa::VerifyingKey<MlDsa65>>,
    // Store the seed, as it can't be extracted from the ml_dsa keys currently
    #[debug("..")]
    ml_dsa_seed: [u8; ML_DSA65_KEY_LEN],
}

impl Eq for SecretKey {}

impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlDsa65Ed25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            ed25519: value.ed25519.verifying_key(),
            ml_dsa: value.ml_dsa_verify.clone(),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let ed25519 = ed25519_dalek::SigningKey::generate(rng);
        let mut ml_dsa_seed = [0u8; ML_DSA65_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = MlDsa65::key_gen_internal(&ml_dsa_seed.into());

        SecretKey {
            ed25519,
            ml_dsa_sign: Box::new(ml_dsa.signing_key().clone()),
            ml_dsa_verify: Box::new(ml_dsa.verifying_key().clone()),
            ml_dsa_seed,
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(ed25519: [u8; 32], ml_dsa: [u8; 32]) -> Result<Self> {
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519);
        // use the seed format
        let keypair = MlDsa65::key_gen_internal(&ml_dsa.into());

        Ok(Self {
            ed25519,
            ml_dsa_sign: Box::new(keypair.signing_key().clone()),
            ml_dsa_verify: Box::new(keypair.verifying_key().clone()),
            ml_dsa_seed: ml_dsa,
        })
    }

    /// Returns the individual secret keys in their raw byte level representation.
    /// The first is the `ed25519` and the second the `ml dsa 65` key.
    pub fn as_bytes(&self) -> (&[u8; ED25519_KEY_LEN], &[u8; ML_DSA65_KEY_LEN]) {
        (self.ed25519.as_bytes(), &self.ml_dsa_seed)
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

        let ed25519_sig = self.ed25519.sign(digest);
        let mut bytes = ed25519_sig.to_bytes().to_vec();

        let ml_dsa_sig = self.ml_dsa_sign.sign(digest);
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let (x, ml) = self.as_bytes();
        writer.write_all(x)?;
        writer.write_all(ml)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        ED25519_KEY_LEN + ML_DSA65_KEY_LEN
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    ed_key: &ed25519_dalek::VerifyingKey,
    ml_dsa_key: &ml_dsa::VerifyingKey<MlDsa65>,
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
    ensure_eq!(sig_bytes.len(), 64 + 3309, "invalid signature length");

    let ed_sig = ed25519_dalek::Signature::try_from(&sig_bytes[..64])?;
    ed_key.verify(hashed, &ed_sig)?;

    let ml_sig = sig_bytes[64..].try_into()?;
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
