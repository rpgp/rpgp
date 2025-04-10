use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign)
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only)
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only)
    RSASign = 3,
    /// Elgamal (Encrypt-Only)
    #[cfg_attr(test, proptest(skip))]
    ElgamalEncrypt = 16,
    /// DSA (Digital Signature Algorithm)
    DSA = 17,
    /// Elliptic Curve: RFC 9580 [formerly in RFC 6637]
    ECDH = 18,
    /// ECDSA: RFC 9580 [formerly in RFC 6637]
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    #[cfg_attr(test, proptest(skip))]
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    #[cfg_attr(test, proptest(skip))]
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

    /// ML-KEM-768+X25519
    MlKem768X25519Draft = 105,
    /// ML-KEM-1024+X448
    #[cfg_attr(test, proptest(skip))]
    MlKem1024X448Draft = 106,

    /// Private experimental range (from OpenPGP)
    #[cfg_attr(test, proptest(skip))]
    Private100 = 100,
    #[cfg_attr(test, proptest(skip))]
    Private101 = 101,
    #[cfg_attr(test, proptest(skip))]
    Private102 = 102,
    #[cfg_attr(test, proptest(skip))]
    Private103 = 103,
    #[cfg_attr(test, proptest(skip))]
    Private104 = 104,
    // #[cfg_attr(test, proptest(skip))]
    // Private105 = 105,
    // #[cfg_attr(test, proptest(skip))]
    // Private106 = 106,
    #[cfg_attr(test, proptest(skip))]
    Private107 = 107,
    #[cfg_attr(test, proptest(skip))]
    Private108 = 108,
    #[cfg_attr(test, proptest(skip))]
    Private109 = 109,
    #[cfg_attr(test, proptest(skip))]
    Private110 = 110,

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))]
    Unknown(u8),
}
