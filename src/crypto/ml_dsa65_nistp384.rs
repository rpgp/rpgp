use ml_dsa::{KeyGen, MlDsa65};
use rand::{CryptoRng, Rng};
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    Signer as _, Verifier,
};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, Result},
    ser::Serialize,
    types::{MlDsa65NistP384PublicParams, SignatureBytes},
};

/// Size in bytes of the NIST P384 secret key.
pub const NISTP384_KEY_LEN: usize = 48;

/// Size in bytes of the ML DSA 65 secret key.
pub const ML_DSA65_KEY_LEN: usize = 32;

pub const NISTP384_SIG_LEN: usize = 96;

/// Secret key for ML DSA 65 with NIST P384.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    nistp384: p384::SecretKey,
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

impl From<&SecretKey> for MlDsa65NistP384PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            nistp384: value.nistp384.public_key(),
            ml_dsa: value.ml_dsa_verify.clone(),
        }
    }
}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let nistp384 = p384::SecretKey::random(&mut rng);

        let mut ml_dsa_seed = [0u8; ML_DSA65_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = MlDsa65::key_gen_internal(&ml_dsa_seed.into());

        SecretKey {
            nistp384,
            ml_dsa_sign: Box::new(ml_dsa.signing_key().clone()),
            ml_dsa_verify: Box::new(ml_dsa.verifying_key().clone()),
            ml_dsa_seed,
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        nistp384: [u8; NISTP384_KEY_LEN],
        ml_dsa: [u8; ML_DSA65_KEY_LEN],
    ) -> Result<Self> {
        let nistp384 = p384::SecretKey::from_slice(&nistp384)?;

        // use the seed format
        let keypair = MlDsa65::key_gen_internal(&ml_dsa.into());

        Ok(Self {
            nistp384,
            ml_dsa_sign: Box::new(keypair.signing_key().clone()),
            ml_dsa_verify: Box::new(keypair.verifying_key().clone()),
            ml_dsa_seed: ml_dsa,
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

        let signing_key = p384::ecdsa::SigningKey::from(&self.nistp384);
        let nistp384_sig: p384::ecdsa::Signature = signing_key.sign_prehash(digest)?;

        let mut bytes = nistp384_sig.to_bytes().to_vec();

        let ml_dsa_sig = self.ml_dsa_sign.sign(digest);
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp384.to_bytes())?;
        writer.write_all(&self.ml_dsa_seed)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NISTP384_KEY_LEN + ML_DSA65_KEY_LEN
    }
}

/// Verify a signature.
pub fn verify(
    nistp384: &p384::PublicKey,
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
    ensure_eq!(
        sig_bytes.len(),
        NISTP384_SIG_LEN + 3309,
        "invalid signature length"
    );

    let pk = p384::ecdsa::VerifyingKey::from_affine(nistp384.as_affine().to_owned())?;
    let nistp384_sig = p384::ecdsa::Signature::try_from(&sig_bytes[..NISTP384_SIG_LEN])?;
    pk.verify_prehash(hashed, &nistp384_sig)?;

    let ml_sig = sig_bytes[NISTP384_SIG_LEN..].try_into()?;
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
