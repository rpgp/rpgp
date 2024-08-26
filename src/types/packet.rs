use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use crate::errors::Result;

/// Represents a Packet. A packet is the record structure used to encode a chunk of data in OpenPGP.
/// Ref: <https://tools.ietf.org/html/rfc4880.html#section-4>
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
    Indeterminate,
    Partial(usize),
}

impl From<usize> for PacketLength {
    fn from(val: usize) -> PacketLength {
        PacketLength::Fixed(val)
    }
}

/// Packet Type ID, see <https://www.rfc-editor.org/rfc/rfc9580.html#packet-types>
///
/// The "Packet Type ID" was called "Packet tag" in RFC 4880 (Section 4.3 "Packet Tags").
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#appendix-B.1-3.7.1>
///
/// However, rPGP will continue to use the term "(Packet) Tag" for the time being.
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
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
    /// Padding Packet
    Padding = 21,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Tag {
    /// Packet Type ID encoded in OpenPGP format
    /// (bits 7 and 6 set, bits 5-0 carry the packet type ID)
    pub fn encode(self) -> u8 {
        let t: u8 = self.into();
        0b1100_0000 | t
    }
}

/// The version of the packet format.
///
/// There are two packet formats
/// (see https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers):
///
/// 1) the (current) OpenPGP packet format specified by this document and its
/// predecessors [RFC4880] and [RFC2440] and
///
/// 2) the Legacy packet format as used by implementations predating any IETF specification of OpenPGP.
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[derive(Default)]
pub enum Version {
    /// Old Packet Format ("Legacy packet format")
    Old = 0,
    /// New Packet Format ("OpenPGP packet format")
    #[default]
    New = 1,
}

impl Version {
    pub fn write_header(self, writer: &mut impl io::Write, tag: u8, len: usize) -> Result<()> {
        debug!("write_header {:?} {} {}", self, tag, len);

        match self {
            Version::Old => {
                if len < 256 {
                    // one octet
                    writer.write_u8(0b1000_0000 | tag << 2)?;
                    writer.write_u8(len.try_into()?)?;
                } else if len < 65536 {
                    // two octets
                    writer.write_u8(0b1000_0001 | tag << 2)?;
                    writer.write_u16::<BigEndian>(len as u16)?;
                } else {
                    // four octets
                    writer.write_u8(0b1000_0010 | tag << 2)?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
            Version::New => {
                writer.write_u8(0b1100_0000 | tag)?;
                if len < 192 {
                    writer.write_u8(len.try_into()?)?;
                } else if len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
        }

        Ok(())
    }
}

// TODO: find a better place for this
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

impl KeyVersion {
    /// Size of OpenPGP fingerprint in bytes
    /// (returns `None` for unknown versions)
    pub const fn fingerprint_len(&self) -> Option<usize> {
        match self {
            KeyVersion::V2 | KeyVersion::V3 => Some(16), // MD5
            KeyVersion::V4 => Some(20),                  // SHA1
            KeyVersion::V5 | KeyVersion::V6 => Some(32), // SHA256
            KeyVersion::Other(_) => None,
        }
    }
}

impl Default for KeyVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_write_header() {
        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::UserAttribute.into(), 12875)
            .unwrap();

        assert_eq!(hex::encode(buf), "d1ff0000324b");

        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::Signature.into(), 302)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06e");

        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::Signature.into(), 303)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06f");
    }
}
