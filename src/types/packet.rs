use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use bytes::Buf;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use crate::errors::Result;
use crate::parsing::BufParsing;

/// Represents the packet length.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PacketLength {
    Fixed(usize), // TODO: make u32
    Indeterminate,
    Partial(u32),
}

impl PacketLength {
    pub fn from_buf<B: Buf>(mut i: B) -> Result<Self> {
        let olen = i.read_u8()?;
        let len = match olen {
            // One-Octet Lengths
            0..=191 => PacketLength::Fixed(olen.into()),
            // Two-Octet Lengths
            192..=223 => {
                let a = i.read_u8()?;
                let l = ((olen as usize - 192) << 8) + 192 + a as usize;
                PacketLength::Fixed(l)
            }
            // Partial Body Lengths
            224..=254 => PacketLength::Partial(1 << (olen as usize & 0x1F)),
            // Five-Octet Lengths
            255 => {
                let len = i.read_be_u32()?;
                PacketLength::Fixed(len.try_into()?)
            }
        };
        Ok(len)
    }

    /// Returns the length in bytes, if it is specified.
    pub fn maybe_len(&self) -> Option<usize> {
        match self {
            Self::Fixed(len) => Some(*len),
            Self::Indeterminate => None,
            Self::Partial(len) => Some(*len as usize),
        }
    }
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
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
    #[cfg_attr(test, proptest(skip))]
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
/// (see <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers>):
///
/// 1) the (current) OpenPGP packet format specified by this document and its
///    predecessors RFC 4880 and RFC 2440 and
///
/// 2) the Legacy packet format as used by implementations predating any IETF specification of OpenPGP.
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[derive(Default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum PacketHeaderVersion {
    /// Old Packet Format ("Legacy packet format")
    Old = 0,
    /// New Packet Format ("OpenPGP packet format")
    #[default]
    New = 1,
}

impl PacketHeaderVersion {
    pub fn write_header(self, writer: &mut impl io::Write, tag: Tag, len: usize) -> Result<()> {
        debug!("write_header {:?} {:?} {}", self, tag, len);
        let tag: u8 = tag.into();
        match self {
            PacketHeaderVersion::Old => {
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
            PacketHeaderVersion::New => {
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

    /// Length of the header, in bytes.
    pub fn header_len(self, len: usize) -> usize {
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    // one octet
                    2
                } else if len < 65536 {
                    // two octets
                    3
                } else {
                    // four octets
                    5
                }
            }
            PacketHeaderVersion::New => {
                if len < 192 {
                    2
                } else if len < 8384 {
                    3
                } else {
                    6
                }
            }
        }
    }
}

// TODO: find a better place for this
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    #[cfg_attr(test, proptest(skip))] // mostly not implemented
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))]
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum PkeskVersion {
    V3 = 3,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SkeskVersion {
    V4 = 4,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_write_header() {
        let mut buf = Vec::new();
        PacketHeaderVersion::New
            .write_header(&mut buf, Tag::UserAttribute, 12875)
            .unwrap();

        assert_eq!(hex::encode(buf), "d1ff0000324b");

        let mut buf = Vec::new();
        PacketHeaderVersion::New
            .write_header(&mut buf, Tag::Signature, 302)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06e");

        let mut buf = Vec::new();
        PacketHeaderVersion::New
            .write_header(&mut buf, Tag::Signature, 303)
            .unwrap();

        assert_eq!(hex::encode(buf), "c2c06f");
    }

    impl Arbitrary for PacketLength {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                (1..=u32::MAX).prop_map(|l| PacketLength::Fixed(l as usize)),
                Just(PacketLength::Indeterminate),
                (1u32..=30).prop_map(|l: u32| PacketLength::Partial(2u32.pow(l))),
            ]
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn header_len(version: PacketHeaderVersion, len: usize) {
            let mut buf = Vec::new();
            version.write_header(&mut buf, Tag::Signature, len).unwrap();
            assert_eq!(buf.len(), version.header_len(len));
        }
    }
}
