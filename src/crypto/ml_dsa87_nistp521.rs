use ecdsa::SigningKey;
use ml_dsa::{KeyGen, MlDsa87};
use p521::NistP521;
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
    types::{MlDsa87NistP521PublicParams, SignatureBytes},
};

/// Size in bytes of the NIST P521 secret key.
pub const NISTP521_KEY_LEN: usize = 66;

/// Size in bytes of the ML DSA 87 secret key.
pub const ML_DSA87_KEY_LEN: usize = 32;

pub const NISTP521_SIG_LEN: usize = 132;

/// Secret key for ML DSA 87 with NIST P521.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    nistp521: p521::SecretKey,
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

impl From<&SecretKey> for MlDsa87NistP521PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            nistp521: value.nistp521.public_key(),
            ml_dsa: value.ml_dsa_verify.clone(),
        }
    }
}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let nistp521 = p521::SecretKey::random(&mut rng);

        let mut ml_dsa_seed = [0u8; ML_DSA87_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = MlDsa87::key_gen_internal(&ml_dsa_seed.into());

        SecretKey {
            nistp521,
            ml_dsa_sign: Box::new(ml_dsa.signing_key().clone()),
            ml_dsa_verify: Box::new(ml_dsa.verifying_key().clone()),
            ml_dsa_seed,
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        nistp521: [u8; NISTP521_KEY_LEN],
        ml_dsa: [u8; ML_DSA87_KEY_LEN],
    ) -> Result<Self> {
        let nistp521 = p521::SecretKey::from_slice(&nistp521)?;

        // use the seed format
        let keypair = MlDsa87::key_gen_internal(&ml_dsa.into());

        Ok(Self {
            nistp521,
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

        let secret: SigningKey<NistP521> = (&self.nistp521).into();
        let signing_key = p521::ecdsa::SigningKey::from(secret);

        let nistp521_sig: p521::ecdsa::Signature = signing_key.sign_prehash(digest)?;

        let mut bytes = nistp521_sig.to_bytes().to_vec();

        let ml_dsa_sig = self.ml_dsa_sign.sign(digest);
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp521.to_bytes())?;
        writer.write_all(&self.ml_dsa_seed)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NISTP521_KEY_LEN + ML_DSA87_KEY_LEN
    }
}

/// Verify a signature.
pub fn verify(
    nistp521: &p521::PublicKey,
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
    ensure_eq!(
        sig_bytes.len(),
        NISTP521_SIG_LEN + 4627,
        "invalid signature length"
    );

    let pk = p521::ecdsa::VerifyingKey::from_affine(nistp521.as_affine().to_owned())?;
    let nistp521_sig = p521::ecdsa::Signature::try_from(&sig_bytes[..NISTP521_SIG_LEN])?;
    pk.verify_prehash(hashed, &nistp521_sig)?;

    let ml_sig = sig_bytes[NISTP521_SIG_LEN..].try_into()?;
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
