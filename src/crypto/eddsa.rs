use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::Signer;
use crate::errors::Result;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, derive_more::Debug)]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    pub secret: [u8; 32],
    #[debug("{}", hex::encode(oid))]
    pub oid: Vec<u8>,
}

impl Signer for SecretKey {
    fn sign(
        &self,
        _hash: HashAlgorithm,
        digest: &[u8],
        pub_params: &PublicParams,
    ) -> Result<Vec<Vec<u8>>> {
        let PublicParams::EdDSA { curve, q } = pub_params else {
            bail!("invalid public params");
        };
        if curve != &ECCCurve::Ed25519 {
            unsupported_err!("curve {:?} for EdDSA", curve.to_string());
        }

        ensure_eq!(q.len(), 33, "invalid Q (len)");
        ensure_eq!(q[0], 0x40, "invalid Q (prefix)");

        let key = ed25519_dalek::SigningKey::from_bytes(&self.secret);

        let signature = key.sign(digest);
        let bytes = signature.to_bytes();

        let r = bytes[..32].to_vec();
        let s = bytes[32..].to_vec();

        Ok(vec![r, s])
    }
}

/// Generate an EdDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(mut rng: R) -> (PublicParams, PlainSecretParams) {
    let mut bytes = Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *bytes);
    let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let public = ed25519_dalek::VerifyingKey::from(&secret);

    // public key
    let mut q = Vec::with_capacity(33);
    q.push(0x40);
    q.extend_from_slice(&public.to_bytes());

    // secret key
    let p = Mpi::from_raw_slice(&secret.to_bytes());
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

            let pk =
                ed25519_dalek::VerifyingKey::from_bytes(&q[1..].try_into().expect("pre verified"))?;
            let mut sig_bytes = vec![0u8; 64];
            // add padding if the values were encoded short
            sig_bytes[(32 - r.len())..32].copy_from_slice(r);
            sig_bytes[32 + (32 - s.len())..].copy_from_slice(s);

            let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)?;

            pk.verify(hashed, &sig)?;

            Ok(())
        }
        _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
    }
}
