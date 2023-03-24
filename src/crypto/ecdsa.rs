use rand::{CryptoRng, Rng};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::errors::Result;
use crate::types::EcdsaPublicParams;
use crate::types::{ECDSASecretKey, Mpi, PlainSecretParams, PublicParams};

/// Generate an ECDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    rng: &mut R,
    curve: ECCCurve,
) -> Result<(PublicParams, PlainSecretParams)> {
    match curve {
        ECCCurve::P256 => {
            let secret = p256::SecretKey::random(rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::P256(public)),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        ECCCurve::P384 => {
            let secret = p384::SecretKey::random(rng);
            let public = secret.public_key();
            let secret = Mpi::from_raw_slice(secret.to_bytes().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::P384(public)),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        _ => unsupported_err!("curve {:?} for ECDSA", curve),
    }
}

/// Verify an ECDSA signature.
pub fn verify(
    p: &EcdsaPublicParams,
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    match p {
        EcdsaPublicParams::P256(p) => {
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
            let pk = p256::ecdsa::VerifyingKey::from_affine(p.as_affine().to_owned())?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::P384(p) => {
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

            let pk = p384::ecdsa::VerifyingKey::from_affine(p.as_affine().to_owned())?;
            let sig = p384::ecdsa::Signature::try_from(&sig_bytes[..])?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        EcdsaPublicParams::Unsupported { curve, .. } => {
            unsupported_err!("curve {:?} for ECDSA", curve.to_string())
        }
    }
}

/// Sign using ECDSA
pub fn sign(
    secret_key: &ECDSASecretKey,
    _hash: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let (r, s) = match secret_key {
        ECDSASecretKey::P256(secret_key) => {
            let secret = p256::ecdsa::SigningKey::from(secret_key);
            let signature: p256::ecdsa::Signature = secret.sign_prehash(digest)?;
            let (r, s) = signature.split_bytes();
            (r.to_vec(), s.to_vec())
        }
        ECDSASecretKey::P384(secret_key) => {
            let secret = p384::ecdsa::SigningKey::from(secret_key);
            let signature: p384::ecdsa::Signature = secret.sign_prehash(digest)?;
            let (r, s) = signature.split_bytes();
            (r.to_vec(), s.to_vec())
        }
        ECDSASecretKey::Unsupported { curve, .. } => {
            unsupported_err!("curve {:?} for ECDSA", curve)
        }
    };

    Ok(vec![r, s])
}
