use ecdsa::SigningKey;
use elliptic_curve::sec1::ToEncodedPoint;
use p521::NistP521;
use rand::{CryptoRng, Rng};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use zeroize::ZeroizeOnDrop;

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::Signer;
use crate::errors::Result;
use crate::types::EcdsaPublicParams;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
pub enum SecretKey {
    P256(#[debug("..")] p256::SecretKey),
    P384(#[debug("..")] p384::SecretKey),
    P521(#[debug("..")] p521::SecretKey),
    Secp256k1(#[debug("..")] k256::SecretKey),
    Unsupported {
        /// The secret point.
        #[debug("..")]
        x: Mpi,
        #[zeroize(skip)]
        curve: ECCCurve,
    },
}

impl Signer for SecretKey {
    fn sign(
        &self,
        hash: HashAlgorithm,
        digest: &[u8],
        pub_params: &PublicParams,
    ) -> Result<Vec<Vec<u8>>> {
        ensure!(
            matches!(pub_params, PublicParams::ECDSA(..)),
            "invalid public params"
        );

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
                (r.to_vec(), s.to_vec())
            }
            Self::P384(secret_key) => {
                let secret = p384::ecdsa::SigningKey::from(secret_key);
                let signature: p384::ecdsa::Signature = secret.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (r.to_vec(), s.to_vec())
            }
            Self::P521(secret_key) => {
                let secret: SigningKey<NistP521> = secret_key.into();
                let signing_key = p521::ecdsa::SigningKey::from(secret);
                let signature: p521::ecdsa::Signature = signing_key.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (r.to_vec(), s.to_vec())
            }
            Self::Secp256k1(secret_key) => {
                let secret = k256::ecdsa::SigningKey::from(secret_key);
                let signature: k256::ecdsa::Signature = secret.sign_prehash(digest)?;
                let (r, s) = signature.split_bytes();
                (r.to_vec(), s.to_vec())
            }
            Self::Unsupported { curve, .. } => {
                unsupported_err!("curve {:?} for ECDSA", curve)
            }
        };

        Ok(vec![r, s])
    }
}

impl SecretKey {
    pub(crate) fn secret_key_length(&self) -> Option<usize> {
        match self {
            Self::P256 { .. } => Some(32),
            Self::P384 { .. } => Some(48),
            Self::P521 { .. } => Some(66),
            Self::Secp256k1 { .. } => Some(32),
            Self::Unsupported { .. } => None,
        }
    }
}
/// Generate an ECDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    mut rng: R,
    curve: &ECCCurve,
) -> Result<(PublicParams, PlainSecretParams)> {
    match curve {
        ECCCurve::P256 => {
            let secret = p256::SecretKey::random(&mut rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::P256 {
                    key: public,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                }),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        ECCCurve::P384 => {
            let secret = p384::SecretKey::random(&mut rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::P384 {
                    key: public,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                }),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        ECCCurve::P521 => {
            let secret = p521::SecretKey::random(&mut rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::P521 {
                    key: public,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                }),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        ECCCurve::Secp256k1 => {
            let secret = k256::SecretKey::random(&mut rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::Secp256k1 {
                    key: public,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                }),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        _ => unsupported_err!("curve {:?} for ECDSA", curve),
    }
}

/// Verify an ECDSA signature.
pub fn verify(
    p: &EcdsaPublicParams,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    if let Some(field_size) = p.secret_key_length() {
        // Error out for size mismatches that would get rejected in ecdsa::hazmat::bits2field
        ensure!(
            hashed.len() >= field_size / 2,
            "Hash algorithm {:?} cannot be combined with key {:?}",
            hash,
            p
        );
    }

    match p {
        EcdsaPublicParams::P256 { key, .. } => {
            const FLEN: usize = 32;
            ensure_eq!(sig.len(), 2);
            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();
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

            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();

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

            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();

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
            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();
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
