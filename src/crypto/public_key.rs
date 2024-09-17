use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign)
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only)
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only)
    RSASign = 3,
    /// Elgamal (Sign-Only)
    ElgamalSign = 16,
    /// DSA (Digital Signature Algorithm)
    DSA = 17,
    /// Elliptic Curve: RFC-6637
    ECDH = 18,
    /// ECDSA: RFC-6637
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
    /// EdDSA legacy format [deprecated in RFC 9580, superseded by Ed25519 (27)]
    EdDSALegacy = 22,

    /// X25519 [RFC 9580]
    X25519 = 25,
    /// X448 [RFC 9580]
    X448 = 26,
    /// Ed25519 [RFC 9580]
    Ed25519 = 27,
    /// Ed448 [RFC 9580]
    Ed448 = 28,

    /// Private experimental range (from OpenPGP)
    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Unknown(u8),
}
