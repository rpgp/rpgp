use std::fmt;

use num_bigint::BigUint;
use rsa::RsaPrivateKey;
use zeroize::Zeroize;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug)]
pub enum SecretKeyRepr {
    RSA(RsaPrivateKey),
    DSA(DSASecretKey),
    ECDSA(ECDSASecretKey),
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

/// Secret key for ECDH with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
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
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
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

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct ECDSASecretKey {
    /// The secret point.
    pub x: BigUint,
    pub oid: Vec<u8>,
}

impl fmt::Debug for ECDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDSASecretKey")
            .field("x", &"[..]")
            .field("oid", &hex::encode(&self.oid))
            .finish()
    }
}

/// Secret key for DSA.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct DSASecretKey {
    x: BigUint,
}

impl fmt::Debug for DSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DSASecretKey").field("x", &"[..]").finish()
    }
}
