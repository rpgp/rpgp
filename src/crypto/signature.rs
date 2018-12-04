use ed25519_dalek;
use num_bigint::BigUint;
use sha2;
use try_from::TryInto;

use crypto::ecc_curve::ECCCurve;
use crypto::hash::HashAlgorithm;
use errors::Result;
use rsa::{self, padding, RSAPublicKey};

/// Verify a RSA, PKCS1v15 padded signature.
pub fn verify_rsa(
    n: &BigUint,
    e: &BigUint,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[u8],
) -> Result<()> {
    let key = RSAPublicKey::new(n.clone(), e.clone())?;
    let rsa_hash: Option<rsa::hash::Hashes> = hash.try_into().ok();

    info!("n: {}", hex::encode(n.to_bytes_be()));
    info!("e: {}", hex::encode(e.to_bytes_be()));
    key.verify(
        padding::PaddingScheme::PKCS1v15,
        rsa_hash.as_ref(),
        &hashed[..],
        sig,
    )
    .map_err(|err| err.into())
}

/// Verify an EdDSA signature.
pub fn verify_eddsa(
    curve: &ECCCurve,
    q: &[u8],
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig: &[Vec<u8>],
) -> Result<()> {
    match *curve {
        ECCCurve::Ed25519 => {
            ensure_eq!(sig.len(), 2);

            let r = &sig[0];
            let s = &sig[1];

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

            pk.verify::<sha2::Sha512>(hashed, &sig)?;

            Ok(())
        }
        _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
    }
}
