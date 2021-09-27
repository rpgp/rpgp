use generic_array::GenericArray;

use crate::crypto::{ECCCurve, HashAlgorithm};
use crate::errors::Result;
use crate::types::Mpi;

/// Verify an EcDSA signature.
pub fn verify(
    curve: &ECCCurve,
    p: &[u8],
    hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    match *curve {
        ECCCurve::BrainpoolP256r1 | ECCCurve::BrainpoolP384r1 | ECCCurve::BrainpoolP512r1 => {
            unimplemented_err!("ECDSA: {}", curve.to_string())
        }
        ECCCurve::P384 | ECCCurve::P521 => {
            unimplemented_err!("ECDSA: {}", curve.to_string())
        }
        ECCCurve::Secp256k1 => {
            unimplemented_err!("ECDSA: {}", curve.to_string())
        }
        ECCCurve::P256 => {
            use ecdsa::hazmat::VerifyPrimitive;
            use p256::ecdsa::VerifyingKey;
            ensure_eq!(sig.len(), 2);

            let mut r = GenericArray::default();
            let mut s = GenericArray::default();

            // add padding if the values were encoded short
            let r_raw = sig[0].as_bytes();
            let s_raw = sig[1].as_bytes();
            ensure!(r_raw.len() < 33, "invalid R (len)");
            ensure!(s_raw.len() < 33, "invalid S (len)");

            r[(32 - r_raw.len())..].copy_from_slice(r_raw);
            s[(32 - s_raw.len())..].copy_from_slice(s_raw);

            let signature = ecdsa::Signature::from_scalars(r, s)?;

            ensure_eq!(p.len(), 1 + 32 + 32, "invalid P (len)");
            ensure_eq!(p[0], 0x04, "invalid P (prefix)");
            // TODO: verify the hashed length matches the HashAlgorithm

            let pk = VerifyingKey::from_sec1_bytes(&p)?;
            let pk: p256::PublicKey = pk.into();
            let affine = pk.as_affine();

            // Select the leftmost 256 bits
            let z = GenericArray::from_slice(&hashed[..32]);
            let prehashed = p256::Scalar::from_bytes_reduced(z);
            affine.verify_prehashed(&prehashed, &signature)?;

            Ok(())
        }
        _ => unsupported_err!("curve {:?} for EcDSA", curve.to_string()),
    }
}
