use ed25519_dalek::Keypair;
use rand::{CryptoRng, Rng};
use zeroize::Zeroize;

use crate::crypto::{ECCCurve, HashAlgorithm};
use crate::errors::Result;
use crate::types::{EdDSASecretKey, Mpi, PlainSecretParams, PublicParams};

/// Generate an EdDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(rng: &mut R) -> (PublicParams, PlainSecretParams) {
    let keypair = Keypair::generate(rng);
    let mut bytes = keypair.to_bytes();

    // public key
    let mut q = Vec::with_capacity(33);
    q.push(0x40);
    q.extend_from_slice(&bytes[32..]);

    // secret key
    let p = Mpi::from_raw_slice(&bytes[..32]);
    bytes.zeroize();

    (
        PublicParams::EdDSA {
            curve: ECCCurve::Ed25519,
            q: q.into(),
        },
        PlainSecretParams::EdDSA(p),
    )
}

/// Verify an EdDSA signature.
pub fn verify(
    curve: &ECCCurve,
    q: &[u8],
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Mpi],
) -> Result<()> {
    match *curve {
        ECCCurve::Ed25519 => {
            ensure_eq!(sig.len(), 2);

            let r = sig[0].as_bytes();
            let s = sig[1].as_bytes();

            ensure!(r.len() < 33, "invalid R (len)");
            ensure!(s.len() < 33, "invalid S (len)");
            ensure_eq!(q.len(), 33, "invalid Q (len)");
            ensure_eq!(q[0], 0x40, "invalid Q (prefix)");

            let pk = ed25519_dalek::PublicKey::from_bytes(&q[1..])?;
            let mut sig_bytes = vec![0u8; 64];
            // add padding if the values were encoded short
            sig_bytes[(32 - r.len())..32].copy_from_slice(r);
            sig_bytes[32 + (32 - s.len())..].copy_from_slice(s);

            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes)?;

            pk.verify(hashed, &sig)?;

            Ok(())
        }
        _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
    }
}

/// Sign using RSA, with PKCS1v15 padding.
pub fn sign(
    q: &[u8],
    secret_key: &EdDSASecretKey,
    _hash: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<Vec<u8>>> {
    ensure_eq!(q.len(), 33, "invalid Q (len)");
    ensure_eq!(q[0], 0x40, "invalid Q (prefix)");

    let mut kp_bytes = vec![0u8; 64];
    kp_bytes[..32].copy_from_slice(&secret_key.secret);
    kp_bytes[32..].copy_from_slice(&q[1..]);
    let kp = ed25519_dalek::Keypair::from_bytes(&kp_bytes)?;

    let signature = kp.sign(digest);
    let bytes = signature.to_bytes();

    let r = bytes[..32].to_vec();
    let s = bytes[32..].to_vec();

    Ok(vec![r, s])
}
