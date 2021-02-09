use std::fmt;

use num_bigint::BigUint;
use rsa::RsaPrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;

use super::Mpi;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug, ZeroizeOnDrop)]
pub enum SecretKeyRepr {
    RSA(RsaPrivateKey),
    DSA(DSASecretKey),
    ECDSA(ECDSASecretKey),
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

/// Secret key for ECDH with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ECDHSecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl fmt::Debug for ECDHSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDHSecretKey")
            .field("secret", &"[..]")
            .field("hash", &self.hash)
            .field("oid", &hex::encode(&self.oid))
            .field("alg_sym", &self.alg_sym)
            .finish()
    }
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EdDSASecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for EdDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdDSASecretKey")
            .field("secret", &"[..]")
            .field("oid", &hex::encode(&self.oid))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum ECDSASecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Secp256k1(k256::SecretKey),
    Unsupported {
        /// The secret point.
        x: Mpi,
        #[zeroize(skip)]
        curve: ECCCurve,
    },
}

impl fmt::Debug for ECDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ECDSASecretKey::P256(_) => write!(f, "ECDSASecretKey::P256([..])"),
            ECDSASecretKey::P384(_) => write!(f, "ECDSASecretKey::P384([..])"),
            ECDSASecretKey::Secp256k1(_) => write!(f, "ECDSASecretKey::Secp256k1([..])"),
            ECDSASecretKey::Unsupported { curve, .. } => f
                .debug_struct("ECDSASecretKey::Unsupported")
                .field("x", &"[..]")
                .field("curve", &curve)
                .finish(),
        }
    }
}

/// Secret key for DSA.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DSASecretKey {
    pub x: BigUint,
}

impl fmt::Debug for DSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DSASecretKey").field("x", &"[..]").finish()
    }
}
