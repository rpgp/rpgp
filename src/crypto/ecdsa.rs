use elliptic_curve::sec1::ToEncodedPoint;
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
                PublicParams::ECDSA(EcdsaPublicParams::P256 {
                    key: public,
                    p: Mpi::from_raw_slice(public.to_encoded_point(false).as_bytes()),
                }),
                PlainSecretParams::ECDSA(secret),
            ))
        }

        ECCCurve::P384 => {
            let secret = p384::SecretKey::random(rng);
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

        ECCCurve::Secp256k1 => {

            let secret = libsecp256k1::SecretKey::random(rng);
            let public = libsecp256k1::PublicKey::from_secret_key(&secret);
            let secret = Mpi::from_raw_slice(secret.serialize().as_slice());

            Ok((
                PublicParams::ECDSA(EcdsaPublicParams::Secp256k1 {
                    key: public,
                    p: Mpi::from_raw_slice(public.serialize().as_slice()),
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
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
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

            let signature = libsecp256k1::Signature::parse_standard(&sig_bytes).unwrap();
            let message = libsecp256k1::Message::parse(&hashed.try_into().unwrap());
            let verified = libsecp256k1::verify(&message, &signature, key);
            if !verified {
                return Err(crate::errors::Error::SignatureError(signature::Error::new()))
            }

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
        ECDSASecretKey::Secp256k1(secret_key) => {
            let message = libsecp256k1::Message::parse(&digest.try_into().unwrap());
            let (signature, _) = libsecp256k1::sign(&message, secret_key);
            (signature.r.b32().to_vec(), signature.s.b32().to_vec())
        }
        ECDSASecretKey::Unsupported { curve, .. } => {
            unsupported_err!("curve {:?} for ECDSA", curve)
        }
    };

    Ok(vec![r, s])
}
