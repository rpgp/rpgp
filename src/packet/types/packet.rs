use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;

// const OID_ECC_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// const OID_ECC_P384: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
// const OID_ECC_P521: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x23];

/// Represents a Packet. A packet is the record structure used to encode a chunk of data in OpenPGP.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet {
    /// Indicator if this is an old or new versioned packet
    pub version: Version,
    /// Denotes the type of data this packet holds
    pub tag: Tag,
    /// The raw bytes of the packet
    pub body: Vec<u8>,
}

/// Represents the packet length.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PacketLength {
    Fixed(usize),
    Indeterminated,
}

impl From<usize> for PacketLength {
    fn from(val: usize) -> PacketLength {
        PacketLength::Fixed(val)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, FromPrimitive)]
pub enum Tag {
    /// Public-Key Encrypted Session Key Packet
    PublicKeyEncryptedSessionKey = 1,
    /// Signature Packet
    Signature = 2,
    /// Symmetric-Key Encrypted Session Key Packet
    SymKeyEncryptedSessionKey = 3,
    /// One-Pass Signature Packet
    OnePassSignature = 4,
    /// Secret-Key Packet
    SecretKey = 5,
    /// Public-Key Packet
    PublicKey = 6,
    /// Secret-Subkey Packet
    SecretSubkey = 7,
    /// Compressed Data Packet
    CompressedData = 8,
    /// Symmetrically Encrypted Data Packet
    SymEncryptedData = 9,
    /// Marker Packet
    Marker = 10,
    /// Literal Data Packet
    LiteralData = 11,
    /// Trust Packet
    Trust = 12,
    /// User ID Packet
    UserId = 13,
    /// Public-Subkey Packet
    PublicSubkey = 14,
    /// User Attribute Packet
    UserAttribute = 17,
    /// Sym. Encrypted and Integrity Protected Data Packet
    SymEncryptedProtectedData = 18,
    /// Modification Detection Code Packet
    ModDetectionCode = 19,
}

#[derive(Debug, PartialEq, Eq, Clone, FromPrimitive)]
pub enum Version {
    /// Old Packet Format
    Old = 0,
    /// New Packet Format
    New = 1,
}

#[derive(Debug, PartialEq, Eq, Clone, FromPrimitive)]
/// Available compression algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.3
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct User {
    pub id: String,
    pub signatures: Vec<Signature>,
}

impl User {
    pub fn new<S: Into<String>>(id: S, signatures: Vec<Signature>) -> Self {
        User {
            id: id.into(),
            signatures,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign) [HAC]
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only) [HAC]
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only) [HAC]
    RSASign = 3,
    /// Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    ElgamalSign = 16,
    /// DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    DSA = 17,
    /// Elliptic Curve: RFC-6637
    ECDH = 18,
    /// ECDSA: RFC-6637
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
    /// EdDSA (not yet assigned)
    EdDSA = 22,
    /// Private experimental range (from OpenGPG)
    // TODO: genenric Unknown(u8)
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
}
