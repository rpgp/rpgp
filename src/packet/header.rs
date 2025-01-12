use bitfields::bitfield;
use bytes::Buf;

use crate::errors::Result;
use crate::parsing::BufParsing;
use crate::types::{PacketLength, Tag, Version};

/// Represents a packet header.
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers>
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketHeader {
    Old {
        header: OldPacketHeader,
        length: PacketLength,
    },
    New {
        header: NewPacketHeader,
        length: PacketLength,
    },
}

impl PacketHeader {
    /// Parse a single packet header from the given buffer.
    pub fn from_buf<B: Buf>(mut i: B) -> Result<Self> {
        let header = i.read_u8()?;

        let first_two_bits = header & 0b1100_0000;
        match first_two_bits {
            0b1100_0000 => {
                // new starts with 0b11
                let header = NewPacketHeader::from_bits(header);
                let length = PacketLength::from_buf(&mut i)?;
                Ok(PacketHeader::New { header, length })
            }
            0b1000_0000 => {
                // old starts with 0b10
                let header = OldPacketHeader::from_bits(header);
                let length = match header.length_type() {
                    // One-Octet Lengths
                    0 => PacketLength::Fixed(i.read_u8()?.into()),
                    // Two-Octet Lengths
                    1 => PacketLength::Fixed(i.read_be_u16()?.into()),
                    // Four-Octet Lengths
                    2 => PacketLength::Fixed(i.read_be_u32()?.try_into()?),
                    3 => PacketLength::Indeterminate,
                    _ => unreachable!("old packet length type is only 2 bits"),
                };
                Ok(PacketHeader::Old { header, length })
            }
            _ => {
                bail!("unknown packet header version {:b}", header);
            }
        }
    }

    /// Returns the packet header version.
    pub const fn version(&self) -> Version {
        match self {
            Self::Old { .. } => Version::Old,
            Self::New { .. } => Version::New,
        }
    }

    /// Returns the packet length.
    pub fn packet_length(&self) -> PacketLength {
        match self {
            Self::Old { length, .. } => *length,
            Self::New { length, .. } => *length,
        }
    }

    /// Returns the packet tag.
    pub fn tag(&self) -> Tag {
        match self {
            Self::Old { header, .. } => header.tag().into(),
            Self::New { header, .. } => header.tag().into(),
        }
    }
}

/// Old format packet header ("Legacy format")
#[bitfield(u8, order = msb)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OldPacketHeader {
    /// First bit is always 1
    #[bits(1, default = true)]
    _padding: bool,
    /// Version: 0
    #[bits(1, default = false)]
    _version: bool,
    /// Packet Type ID
    #[bits(4)]
    tag: u8,
    /// length-type
    #[bits(2)]
    length_type: u8,
}

/// Parses a new format packet header ("OpenPGP format")
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers>
#[bitfield(u8, order = msb)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NewPacketHeader {
    /// First bit is always 1
    #[bits(1, default = true)]
    _padding: bool,
    /// Version: 1
    #[bits(1, default = true)]
    _version: bool,
    /// Packet Type ID
    #[bits(6)]
    tag: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_length() {
        // # off=5053201 ctb=d1 tag=17 hlen=6 plen=4973 new-ctb
        // :attribute packet: [jpeg image of size 4951]
        let packet_header_raw = hex::decode(b"d1ff0000136d").unwrap();
        let header = PacketHeader::from_buf(&mut &packet_header_raw[..]).unwrap();
        dbg!(&header);

        assert_eq!(header.version(), Version::New);
        assert_eq!(header.tag(), Tag::UserAttribute);
        assert_eq!(header.packet_length(), PacketLength::Fixed(4973));
    }
}
