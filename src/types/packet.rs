use std::io::{self, BufRead};

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use crate::{errors::Result, parsing_reader::BufReadParsing};

/// Represents the packet length.
#[derive(derive_more::Debug, PartialEq, Eq, Clone, Copy)]
pub enum PacketLength {
    Fixed(u32),
    Indeterminate,
    Partial(u32),
}

impl PacketLength {
    /// Returns how many bytes encoding the given length as fixed encoding would need.
    pub fn fixed_encoding_len(len: u32) -> usize {
        if len < 192 {
            1
        } else if len < 8384 {
            2
        } else {
            1 + 4
        }
    }

    pub fn try_from_reader<R: BufRead>(mut r: R) -> std::io::Result<Self> {
        let olen = r.read_u8()?;
        let len = match olen {
            // One-Octet Lengths
            0..=191 => PacketLength::Fixed(olen.into()),
            // Two-Octet Lengths
            192..=223 => {
                let a = r.read_u8()?;
                let l = ((olen as u32 - 192) << 8) + 192 + a as u32;
                PacketLength::Fixed(l)
            }
            // Partial Body Lengths
            224..=254 => PacketLength::Partial(1 << (olen as usize & 0x1F)),
            // Five-Octet Lengths
            255 => {
                let len = r.read_be_u32()?;
                PacketLength::Fixed(len)
            }
        };
        Ok(len)
    }

    /// Returns the length in bytes, if it is specified.
    pub fn maybe_len(&self) -> Option<u32> {
        match self {
            Self::Fixed(len) => Some(*len),
            Self::Indeterminate => None,
            Self::Partial(len) => Some(*len),
        }
    }

    pub fn to_writer_new<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PacketLength::Fixed(len) => {
                if *len < 192 {
                    writer.write_u8(*len as u8)?;
                } else if *len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(*len)?;
                }
            }
            PacketLength::Indeterminate => {
                unreachable!("invalid state: indeterminate lengths for new style packet header");
            }
            PacketLength::Partial(len) => {
                debug_assert_eq!(len.count_ones(), 1); // must be a power of two

                // y & 0x1F
                let n = len.trailing_zeros();
                let n = (224 + n) as u8;
                writer.write_u8(n)?;
            }
        }
        Ok(())
    }
}

/// Packet Type ID, see <https://www.rfc-editor.org/rfc/rfc9580.html#packet-types>
///
/// The "Packet Type ID" was called "Packet tag" in RFC 4880 (Section 4.3 "Packet Tags").
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#appendix-B.1-3.7.1>
///
/// However, rPGP will continue to use the term "(Packet) Tag" for the time being.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
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
    /// "OCB Encrypted Data Packet", a GnuPG proprietary AEAD encryption container format
    /// (not standardized in OpenPGP).
    ///
    /// rPGP only supports decryption, for users who have inadvertently ended up with such data.
    ///
    /// This format was initially outlined in RFC 4880-bis, but superseded by SEIPDv2 in RFC 9580.
    /// See <https://www.ietf.org/archive/id/draft-koch-librepgp-03.html#name-ocb-encrypted-data-packet-t>
    GnupgAead = 20,
    /// Padding Packet
    Padding = 21,

    /// Unassigned Critical Packets [22-39]
    #[cfg_attr(test, proptest(skip))]
    UnassignedCritical(u8),

    /// Unassigned Non-Critical Packets [40-59]
    #[cfg_attr(test, proptest(skip))]
    UnassignedNonCritical(u8),

    /// Private or Experimental Use [60-63]
    #[cfg_attr(test, proptest(skip))]
    Experimental(u8),

    /// Catchall, this should only occur for the (illegal) type IDs 0, 15 and 16
    #[cfg_attr(test, proptest(skip))]
    Other(u8),
}

impl From<Tag> for u8 {
    fn from(value: Tag) -> Self {
        match value {
            Tag::PublicKeyEncryptedSessionKey => 1,
            Tag::Signature => 2,
            Tag::SymKeyEncryptedSessionKey => 3,
            Tag::OnePassSignature => 4,
            Tag::SecretKey => 5,
            Tag::PublicKey => 6,
            Tag::SecretSubkey => 7,
            Tag::CompressedData => 8,
            Tag::SymEncryptedData => 9,
            Tag::Marker => 10,
            Tag::LiteralData => 11,
            Tag::Trust => 12,
            Tag::UserId => 13,
            Tag::PublicSubkey => 14,

            Tag::UserAttribute => 17,
            Tag::SymEncryptedProtectedData => 18,
            Tag::ModDetectionCode => 19,
            Tag::GnupgAead => 20,
            Tag::Padding => 21,

            Tag::UnassignedCritical(id) => id,
            Tag::UnassignedNonCritical(id) => id,
            Tag::Experimental(id) => id,

            Tag::Other(id) => id,
        }
    }
}
impl From<u8> for Tag {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::PublicKeyEncryptedSessionKey,
            2 => Self::Signature,
            3 => Self::SymKeyEncryptedSessionKey,
            4 => Self::OnePassSignature,
            5 => Self::SecretKey,
            6 => Self::PublicKey,
            7 => Self::SecretSubkey,
            8 => Self::CompressedData,
            9 => Self::SymEncryptedData,
            10 => Self::Marker,
            11 => Self::LiteralData,
            12 => Self::Trust,
            13 => Self::UserId,
            14 => Self::PublicSubkey,

            17 => Self::UserAttribute,
            18 => Self::SymEncryptedProtectedData,
            19 => Self::ModDetectionCode,
            20 => Self::GnupgAead,
            21 => Self::Padding,
            22..=39 => Self::UnassignedCritical(value),
            40..=59 => Self::UnassignedNonCritical(value),
            60..=63 => Self::Experimental(value),

            o => Self::Other(o),
        }
    }
}

impl Tag {
    /// Packet Type ID encoded in OpenPGP format
    /// (bits 7 and 6 set, bits 5-0 carry the packet type ID)
    pub const fn encode(self) -> u8 {
        let t = match self {
            Self::PublicKeyEncryptedSessionKey => 1,
            Self::Signature => 2,
            Self::SymKeyEncryptedSessionKey => 3,
            Self::OnePassSignature => 4,
            Self::SecretKey => 5,
            Self::PublicKey => 6,
            Self::SecretSubkey => 7,
            Self::CompressedData => 8,
            Self::SymEncryptedData => 9,
            Self::Marker => 10,
            Self::LiteralData => 11,
            Self::Trust => 12,
            Self::UserId => 13,
            Self::PublicSubkey => 14,
            Self::UserAttribute => 17,
            Self::SymEncryptedProtectedData => 18,
            Self::ModDetectionCode => 19,
            Self::GnupgAead => 20,
            Self::Padding => 21,
            Self::UnassignedCritical(i) => i,
            Self::UnassignedNonCritical(i) => i,
            Self::Experimental(i) => i,
            Self::Other(i) => i,
        };
        0b1100_0000 | t
    }

    pub const fn from_bits(bits: u8) -> Self {
        match bits {
            1 => Self::PublicKeyEncryptedSessionKey,
            2 => Self::Signature,
            3 => Self::SymKeyEncryptedSessionKey,
            4 => Self::OnePassSignature,
            5 => Self::SecretKey,
            6 => Self::PublicKey,
            7 => Self::SecretSubkey,
            8 => Self::CompressedData,
            9 => Self::SymEncryptedData,
            10 => Self::Marker,
            11 => Self::LiteralData,
            12 => Self::Trust,
            13 => Self::UserId,
            14 => Self::PublicSubkey,
            17 => Self::UserAttribute,
            18 => Self::SymEncryptedProtectedData,
            19 => Self::ModDetectionCode,
            21 => Self::Padding,
            22..=39 => Self::UnassignedCritical(bits),
            40..=59 => Self::UnassignedNonCritical(bits),
            60..=63 => Self::Experimental(bits),
            i => Self::Other(i),
        }
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
        debug!("write_header {self:?} {tag:?} {len}");
        let tag: u8 = tag.into();
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    // one octet
                    writer.write_u8(0b1000_0000 | (tag << 2))?;
                    writer.write_u8(len.try_into()?)?;
                } else if len < 65536 {
                    // two octets
                    writer.write_u8(0b1000_0001 | (tag << 2))?;
                    writer.write_u16::<BigEndian>(len as u16)?;
                } else {
                    // four octets
                    writer.write_u8(0b1000_0010 | (tag << 2))?;
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
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, FromPrimitive, IntoPrimitive)]
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
    /// SKESK v4 is the default mechanism for symmetric-key encryption of a session key in
    /// OpenPGP RFC 4880:
    /// <https://www.rfc-editor.org/rfc/rfc4880#section-5.3>
    V4 = 4,

    /// CAUTION: SKESK v5 is a GnuPG-specific format! (It is not standardized as part of OpenPGP)
    ///
    /// See <https://www.ietf.org/archive/id/draft-koch-librepgp-03.html#name-symmetric-key-encrypted-ses>
    V5 = 5,

    /// SKESK v6 is an AEAD-based format for symmetric-key encryption of a session key.
    ///
    /// It was introduced in OpenPGP RFC 9580:
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc>
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

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
                (1..=u32::MAX).prop_map(PacketLength::Fixed),
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
