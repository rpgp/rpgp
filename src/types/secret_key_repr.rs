/// The version of the secret key that is actually exposed to users to do crypto operations.
pub enum SecretKeyRepr {
    RSA(RSAPrivateKey),
    DSA,
    ECDSA,
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

/// Secret key for ECDH with Curve25519, the only combination we currently support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHSecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSASecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for SecretKeyRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SecretKeyRepr::RSA(_) => write!(f, "SecretKeyRepr(RSA)"),
            SecretKeyRepr::DSA => write!(f, "SecretKeyRepr(DSA)"),
            SecretKeyRepr::ECDSA => write!(f, "SecretKeyRepr(ECDSA)"),
            SecretKeyRepr::ECDH(_) => write!(f, "SecretKeyRepr(ECDH)"),
            SecretKeyRepr::EdDSA(_) => write!(f, "SecretKeyRepr(EdDSA)"),
        }
    }
}
