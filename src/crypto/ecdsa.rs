use ecdsa::SigningKey;
use p521::NistP521;
use rand::{CryptoRng, RngCore};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, Signer},
    errors::{bail, ensure, ensure_eq, unsupported_err, Error, Result},
    ser::Serialize,
    types::{EcdsaPublicParams, Mpi, SignatureBytes},
};

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum SecretKey {
    P256(
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p256_gen()"))]
        p256::SecretKey,
    ),
    P384(
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p384_gen()"))]
        p384::SecretKey,
    ),
    P521(
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p521_gen()"))]
        p521::SecretKey,
    ),
    Secp256k1(
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_k256_gen()"))]
        k256::SecretKey,
    ),
    #[cfg_attr(test, proptest(skip))]
    Unsupported {
        /// The secret point.
        #[debug("..")]
        x: Vec<u8>,
        #[zeroize(skip)]
        curve: ECCCurve,
    },
}

impl TryFrom<&SecretKey> for EcdsaPublicParams {
    type Error = Error;

    fn try_from(value: &SecretKey) -> std::result::Result<Self, Self::Error> {
        match value {
            SecretKey::P256(ref p) => Ok(EcdsaPublicParams::P256 {
                key: p.public_key(),
            }),
            SecretKey::P384(ref p) => Ok(EcdsaPublicParams::P384 {
                key: p.public_key(),
            }),
            SecretKey::P521(ref p) => Ok(EcdsaPublicParams::P521 {
                key: p.public_key(),
            }),
            SecretKey::Secp256k1(ref p) => Ok(EcdsaPublicParams::Secp256k1 {
                key: p.public_key(),
            }),
            SecretKey::Unsupported { ref curve, .. } => {
                bail!("unsupported curve, cannot convert: {}", curve);
            }
        }
    }
}

impl SecretKey {
    /// Generate an ECDSA `SecretKey`.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        curve: &ECCCurve,
    ) -> Result<Self> {
        match curve {
            ECCCurve::P256 => {
                let Ok(secret) = p256::SecretKey::try_from_rng(rng);
                Ok(SecretKey::P256(secret))
            }
            ECCCurve::P384 => {
                let Ok(secret) = p384::SecretKey::try_from_rng(rng);
                Ok(SecretKey::P384(secret))
            }
            ECCCurve::P521 => {
                let Ok(secret) = p521::SecretKey::try_from_rng(rng);
                Ok(SecretKey::P521(secret))
            }
            ECCCurve::Secp256k1 => {
                let Ok(secret) = k256::SecretKey::try_from_rng(rng);
                Ok(SecretKey::Secp256k1(secret))
            }
            _ => unsupported_err!("curve {:?} for ECDSA", curve),
        }
    }

    pub(crate) fn try_from_mpi(pub_params: &EcdsaPublicParams, d: Mpi) -> Result<Self> {
        match pub_params {
            EcdsaPublicParams::P256 { .. } => {
                let secret = p256::SecretKey::from_slice(d.as_ref())?;

                Ok(SecretKey::P256(secret))
            }
            EcdsaPublicParams::P384 { .. } => {
                let secret = p384::SecretKey::from_slice(d.as_ref())?;

                Ok(SecretKey::P384(secret))
            }
            EcdsaPublicParams::P521 { .. } => {
                let secret = p521::SecretKey::from_slice(d.as_ref())?;

                Ok(SecretKey::P521(secret))
            }
            EcdsaPublicParams::Secp256k1 { .. } => {
                let secret = k256::SecretKey::from_slice(d.as_ref())?;

                Ok(SecretKey::Secp256k1(secret))
            }
            EcdsaPublicParams::Unsupported { curve, .. } => {
                unsupported_err!("curve {:?} for ECDSA", curve.to_string())
            }
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
            Self::Secp256k1 { .. } => ECCCurve::Secp256k1,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    pub(crate) fn secret_key_length(&self) -> Option<usize> {
        match self {
            Self::P256 { .. } => Some(32),
            Self::P384 { .. } => Some(48),
            Self::P521 { .. } => Some(66),
            Self::Secp256k1 { .. } => Some(32),
            Self::Unsupported { .. } => None,
        }
    }

    fn to_mpi(&self) -> Mpi {
        match self {
            Self::P256(k) => Mpi::from_slice(k.to_bytes().as_ref()),
            Self::P384(k) => Mpi::from_slice(k.to_bytes().as_ref()),
            Self::P521(k) => Mpi::from_slice(k.to_bytes().as_ref()),
            Self::Secp256k1(k) => Mpi::from_slice(k.to_bytes().as_ref()),
            Self::Unsupported { x, .. } => Mpi::from_slice(x),
        }
    }

    /// Returns the secret material as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => k.to_bytes().to_vec(),
            Self::P384(k) => k.to_bytes().to_vec(),
            Self::P521(k) => k.to_bytes().to_vec(),
            Self::Secp256k1(k) => k.to_bytes().to_vec(),
            Self::Unsupported { x, .. } => x.clone(),
        }
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        let x = self.to_mpi();
        x.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        let x = self.to_mpi();
        x.write_len()
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        if let Some(field_size) = self.secret_key_length() {
            // We require that the signing key length is matched by the hash digest length,
            // see https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.2-5

            let field_size = match field_size {
                66 => 64, // nist p521 is treated as though it were 512 bit-sized
                s => s,
            };

            ensure!(
                digest.len() >= field_size,
                "Hash digest size ({:?}) must at least match key size ({:?})",
                hash,
                self
            );
        }

        let (r, s) = match self {
            Self::P256(secret_key) => {
                let secret = p256::ecdsa::SigningKey::from(secret_key);
                let signature: p256::ecdsa::Signature = secret.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (Mpi::from_slice(&r), Mpi::from_slice(&s))
            }
            Self::P384(secret_key) => {
                let secret = p384::ecdsa::SigningKey::from(secret_key);
                let signature: p384::ecdsa::Signature = secret.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (Mpi::from_slice(&r), Mpi::from_slice(&s))
            }
            Self::P521(secret_key) => {
                let secret: SigningKey<NistP521> = secret_key.into();
                let signing_key = p521::ecdsa::SigningKey::from(secret);
                let signature: p521::ecdsa::Signature = signing_key.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (Mpi::from_slice(&r), Mpi::from_slice(&s))
            }
            Self::Secp256k1(secret_key) => {
                let secret = k256::ecdsa::SigningKey::from(secret_key);
                let signature: k256::ecdsa::Signature = secret.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (Mpi::from_slice(&r), Mpi::from_slice(&s))
            }
            Self::Unsupported { curve, .. } => {
                unsupported_err!("curve {:?} for ECDSA", curve)
            }
        };

        Ok(SignatureBytes::Mpis(vec![r, s]))
    }
}

/// Verify an ECDSA signature.
pub fn verify(
    p: &EcdsaPublicParams,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    // NOTE: the `None` case will run into an `unsupported_err`, below, so it's ok not to consider it here
    if let Some(field_size) = p.secret_key_length() {
        // Error out for size mismatches that would get rejected in ecdsa::hazmat::bits2field
        ensure!(
            hashed.len() >= field_size / 2,
            "Hash algorithm {:?} cannot be combined with key {:?}",
            hash,
            p
        );

        // RFC 9580:
        // An ECDSA signature MUST use a hash algorithm with a digest size of at least the curve's "fsize" value [..]"
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.2-5)
        let min_hash_len = match field_size {
            // "[..] except in the case of NIST P-521, for which at least a 512-bit hash algorithm MUST be used"
            521 => 512,

            f => f,
        };
        let Some(digest_size) = hash.digest_size() else {
            bail!("ECDSA signature: invalid hash algorithm: {:?}", hash);
        };
        ensure!(
            digest_size * 8 >= min_hash_len,
            "ECDSA signature: hash algorithm {:?} is too weak for key {:?}",
            hash,
            p
        );
    }

    match p {
        EcdsaPublicParams::P256 { key, .. } => {
            const FLEN: usize = 32;
            ensure_eq!(sig.len(), 2);
            let r = sig[0].as_ref();
            let s = sig[1].as_ref();
            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");
            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let sig = p256::ecdsa::Signature::try_from(&sig_bytes[..])?;
            let pk = p256::ecdsa::VerifyingKey::from_affine(key.as_affine().to_owned())?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::P384 { key, .. } => {
            const FLEN: usize = 48;
            ensure_eq!(sig.len(), 2);

            let r = sig[0].as_ref();
            let s = sig[1].as_ref();

            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");

            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let pk = p384::ecdsa::VerifyingKey::from_affine(key.as_affine().to_owned())?;
            let sig = p384::ecdsa::Signature::try_from(&sig_bytes[..])?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::P521 { key, .. } => {
            const FLEN: usize = 66;
            ensure_eq!(sig.len(), 2);

            let r = sig[0].as_ref();
            let s = sig[1].as_ref();

            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");

            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let pk = p521::ecdsa::VerifyingKey::from_affine(key.as_affine().to_owned())?;
            let sig = p521::ecdsa::Signature::try_from(&sig_bytes[..])?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::Secp256k1 { key, .. } => {
            const FLEN: usize = 32;
            ensure_eq!(sig.len(), 2);
            let r = sig[0].as_ref();
            let s = sig[1].as_ref();
            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");
            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let pk = k256::ecdsa::VerifyingKey::from_affine(key.as_affine().to_owned())?;
            let sig = k256::ecdsa::Signature::try_from(&sig_bytes[..])?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::Unsupported { curve, .. } => {
            unsupported_err!("curve {:?} for ECDSA", curve.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    prop_compose! {
        pub fn key_p256_gen()(seed: u64) -> p256::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            let Ok(key) = p256::SecretKey::try_from_rng(&mut rng);
            key
        }
    }

    prop_compose! {
        pub fn key_p384_gen()(seed: u64) -> p384::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            let Ok(key) = p384::SecretKey::try_from_rng(&mut rng);
            key
        }
    }

    prop_compose! {
        pub fn key_p521_gen()(seed: u64) -> p521::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            let Ok(key) = p521::SecretKey::try_from_rng(&mut rng);
            key
        }
    }

    prop_compose! {
        pub fn key_k256_gen()(seed: u64) -> k256::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            let Ok(key) = k256::SecretKey::try_from_rng(&mut rng);
            key
        }
    }
}
