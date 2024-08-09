use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::Signer;
use crate::errors::Result;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

pub enum Mode {
    EdDSALegacy, // with curve Ed25519
    Ed25519,
}

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
        let curve = match pub_params {
            PublicParams::EdDSALegacy { curve, q } => {
                ensure_eq!(q.len(), 33, "invalid Q (len)");
                ensure_eq!(q[0], 0x40, "invalid Q (prefix)");

                curve
            }
            PublicParams::Ed25519 { .. } => &ECCCurve::Ed25519,
            _ => bail!("invalid public params"),
        };

        if curve != &ECCCurve::Ed25519 {
            unsupported_err!("curve {:?} for EdDSA", curve.to_string());
        }

        let key = ed25519_dalek::SigningKey::from_bytes(&self.secret);

        let signature = key.sign(digest);
        let bytes = signature.to_bytes();

        let r = bytes[..32].to_vec();
        let s = bytes[32..].to_vec();

        Ok(vec![r, s])
    }
}

/// Generate an EdDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    mut rng: R,
    mode: Mode,
) -> (PublicParams, PlainSecretParams) {
    let mut bytes = Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *bytes);
    let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let public = ed25519_dalek::VerifyingKey::from(&secret);

    match mode {
        Mode::EdDSALegacy => {
            // public key
            let mut q = Vec::with_capacity(33);
            q.push(0x40);
            q.extend_from_slice(&public.to_bytes());

            // secret key
            let p = Mpi::from_raw_slice(&secret.to_bytes());
            bytes.zeroize();

            (
                PublicParams::EdDSALegacy {
                    curve: ECCCurve::Ed25519,
                    q: q.into(),
                },
                PlainSecretParams::EdDSALegacy(p),
            )
        }
        Mode::Ed25519 => (
            PublicParams::Ed25519 {
                public: public.to_bytes(),
            },
            PlainSecretParams::Ed25519(secret.to_bytes()),
        ),
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    curve: &ECCCurve,
    public: &[u8],
    _hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    match *curve {
        ECCCurve::Ed25519 => {
            let pk: ed25519_dalek::VerifyingKey = public.try_into()?;
            let sig = sig_bytes.try_into()?;

            Ok(pk.verify(hashed, &sig)?)
        }
        _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
    }
}
