use ml_dsa::{KeyGen, MlDsa87};
use rand::{CryptoRng, RngCore};
use signature::{Signer as _, Verifier};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, Result},
    ser::Serialize,
    types::{MlDsa87Ed448PublicParams, SignatureBytes},
};

/// Size in bytes of the ED448 secret key.
pub const ED448_KEY_LEN: usize = 57;
/// Size in bytes of the ML DSA 87 secret key.
pub const ML_DSA87_KEY_LEN: usize = 32;

/// Secret key for ML DSA 87 with Curve448.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    ed448: ed448_goldilocks::SigningKey,
    #[debug("..")]
    ml_dsa_sign: Box<ml_dsa::SigningKey<MlDsa87>>,
    #[debug("{}", hex::encode(ml_dsa_verify.encode()))]
    ml_dsa_verify: Box<ml_dsa::VerifyingKey<MlDsa87>>,
    // Store the seed, as it can't be extracted from the ml_dsa keys currently
    #[debug("..")]
    ml_dsa_seed: [u8; ML_DSA87_KEY_LEN],
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
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let ed448 = ed448_goldilocks::SigningKey::generate(rng);
        let mut ml_dsa_seed = [0u8; ML_DSA87_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = MlDsa87::key_gen_internal(&ml_dsa_seed.into());

        SecretKey {
            ed448,
            ml_dsa_sign: Box::new(ml_dsa.signing_key().clone()),
            ml_dsa_verify: Box::new(ml_dsa.verifying_key().clone()),
            ml_dsa_seed,
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        ed448: [u8; ED448_KEY_LEN],
        ml_dsa: [u8; ML_DSA87_KEY_LEN],
    ) -> Result<Self> {
        let ed448 = ed448_goldilocks::SigningKey::from(
            ed448_goldilocks::SecretKey::try_from(&ed448[..]).expect("invariant violation"),
        );
        // use the seed format
        let keypair = MlDsa87::key_gen_internal(&ml_dsa.into());

        Ok(Self {
            ed448,
            ml_dsa_sign: Box::new(keypair.signing_key().clone()),
            ml_dsa_verify: Box::new(keypair.verifying_key().clone()),
            ml_dsa_seed: ml_dsa,
        })
    }

    /// Returns the individual secret keys in their raw byte level representation.
    /// The first is the `ed448` and the second the `ml dsa 87` key.
    pub fn as_bytes(&self) -> (&[u8; ED448_KEY_LEN], &[u8; ML_DSA87_KEY_LEN]) {
        let r: &[u8] = self.ed448.as_bytes().as_ref();
        (r.try_into().expect("known size"), &self.ml_dsa_seed)
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
        ED448_KEY_LEN + ML_DSA87_KEY_LEN
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
    ed_key: &ed448_goldilocks::VerifyingKey,
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

    let ed_sig = ed448_goldilocks::Signature::try_from(&sig_bytes[..114])?;
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
