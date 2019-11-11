use std::io;

use byteorder::{BigEndian, WriteBytesExt};

use crate::errors::Result;

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
    Partial(usize),
}

impl From<usize> for PacketLength {
    fn from(val: usize) -> PacketLength {
        PacketLength::Fixed(val)
    }
}

/// Packet tag as defined in RFC 4880, Section 4.3 "Packet Tags"
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
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
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum Version {
    /// Old Packet Format
    Old = 0,
    /// New Packet Format
    New = 1,
}

impl Default for Version {
    fn default() -> Self {
        Version::New
    }
}

impl Version {
    pub fn write_header(self, writer: &mut impl io::Write, tag: u8, len: usize) -> Result<()> {
        info!("write_header {:?} {} {}", self, tag, len);

        match self {
            Version::Old => {
                if len < 256 {
                    writer.write_all(&[0b1000_0000 | tag << 2, len as u8])?;
                } else if len < 65536 {
                    writer.write_all(&[0b1000_0001 | tag << 2])?;
                    writer.write_u16::<BigEndian>(len as u16)?;
                } else {
                    writer.write_all(&[0b1000_0010 | tag << 2])?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
            Version::New => {
                writer.write_all(&[0b1100_0000 | tag])?;

                if len < 192 {
                    writer.write_all(&[len as u8])?;
                } else if len < 8384 {
                    writer.write_all(&[
                        (((len - 192) >> 8) + 192) as u8,
                        ((len - 192) & 0xFF) as u8,
                    ])?;
                } else {
                    writer.write_all(&[255])?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
        }

        Ok(())
    }
}

// TODO: find a better place for this
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl Default for KeyVersion {
    fn default() -> Self {
        KeyVersion::V4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_header() {
        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::UserAttribute as u8, 12875)
            .unwrap();

        assert_eq!(hex::encode(buf), "d1ff0000324b");

        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::Signature as u8, 302)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06e");

        let mut buf = Vec::new();
        Version::New
            .write_header(&mut buf, Tag::Signature as u8, 303)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06f");
    }
}
