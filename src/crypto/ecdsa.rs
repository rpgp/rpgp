use elliptic_curve::sec1::ToEncodedPoint;
use rand::{CryptoRng, Rng};
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    Signature as SigSignature,
};

use crate::crypto::{ECCCurve, HashAlgorithm};
use crate::errors::Result;
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
            Ok((
                PublicParams::ECDSA {
                    curve,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                },
                PlainSecretParams::ECDSA(Mpi::from_raw_slice(secret.to_be_bytes().as_slice())),
            ))
        }

        ECCCurve::P384 => {
            let secret = p384::SecretKey::random(rng);
            let public = secret.public_key();
            Ok((
                PublicParams::ECDSA {
                    curve,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                },
                PlainSecretParams::ECDSA(Mpi::from_raw_slice(secret.to_be_bytes().as_slice())),
            ))
        }

        _ => unsupported_err!("curve {:?} for ECDSA", curve),
    }
}

/// Verify an ECDSA signature.
pub fn verify(
    curve: &ECCCurve,
    p: &[u8],
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    match *curve {
        ECCCurve::P256 => {
            const FLEN: usize = 32;
            ensure_eq!(sig.len(), 2);

            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();

            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");
            ensure_eq!(p.len(), 2 * FLEN + 1, "invalid P (len)");
            ensure_eq!(p[0], 0x04, "invalid P (prefix)");

            let pk = p256::ecdsa::VerifyingKey::from_sec1_bytes(p)?;
            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let sig = p256::ecdsa::Signature::from_bytes(&sig_bytes)?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        ECCCurve::P384 => {
            const FLEN: usize = 48;
            ensure_eq!(sig.len(), 2);

            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();

            ensure!(r.len() <= FLEN, "invalid R (len)");
            ensure!(s.len() <= FLEN, "invalid S (len)");
            ensure_eq!(p.len(), 2 * FLEN + 1, "invalid P (len)");
            ensure_eq!(p[0], 0x04, "invalid P (prefix)");

            let pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(p)?;
            let mut sig_bytes = [0u8; 2 * FLEN];

            // add padding if the values were encoded short
            sig_bytes[(FLEN - r.len())..FLEN].copy_from_slice(r);
            sig_bytes[FLEN + (FLEN - s.len())..].copy_from_slice(s);

            let sig = p384::ecdsa::Signature::from_bytes(&sig_bytes)?;

            pk.verify_prehash(hashed, &sig)?;

            Ok(())
        }
        _ => unsupported_err!("curve {:?} for ECDSA", curve.to_string()),
    }
}

/// Sign using ECDSA
pub fn sign(
    curve: &ECCCurve,
    secret_key: &ECDSASecretKey,
    _hash: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let d = secret_key.x.to_bytes_be();

    let (r, s) = match curve {
        ECCCurve::P256 => {
            let secret = p256::ecdsa::SigningKey::from_bytes(&d)?;
            let signature = secret.sign_prehash(digest)?;
            let (r, s) = signature.split_bytes();
            (r.to_vec(), s.to_vec())
        }
        ECCCurve::P384 => {
            let secret = p384::ecdsa::SigningKey::from_bytes(&d)?;
            let signature = secret.sign_prehash(digest)?;
            let (r, s) = signature.split_bytes();
            (r.to_vec(), s.to_vec())
        }
        _ => unsupported_err!("curve {:?} for ECDSA", curve),
    };

    Ok(vec![r, s])
}
