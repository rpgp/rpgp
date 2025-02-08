use bitfields::bitfield;
use byteorder::{BigEndian, WriteBytesExt};
use bytes::Buf;
use log::debug;

use crate::errors::Result;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{PacketHeaderVersion, PacketLength, Tag};

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

/// Maximum size of partial packet length.
const MAX_PARTIAL_LEN: u32 = 2u32.pow(30);

impl PacketHeader {
    /// Parse a single packet header from the given buffer.
    pub fn from_buf<B: Buf>(mut i: B) -> Result<Self> {
        let header = i.read_u8()?;

        let first_two_bits = header & 0b1100_0000;
        match first_two_bits {
            0b1100_0000 => {
                // new starts with 0b11
                let header = NewPacketHeader::from_bits(header);
                let olen = i.read_u8()?;
                let length = match olen {
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

    pub fn from_parts(
        version: PacketHeaderVersion,
        tag: Tag,
        length: PacketLength,
    ) -> Result<Self> {
        match version {
            PacketHeaderVersion::Old => {
                let typ = match &length {
                    PacketLength::Fixed(len) => old_fixed_type(*len),
                    PacketLength::Indeterminate => 3,
                    PacketLength::Partial(_) => {
                        bail!("partial lengths are only supported in new style headers");
                    }
                };

                Ok(Self::Old {
                    header: OldPacketHeaderBuilder::new()
                        .checked_with_tag(tag.into())
                        .map_err(|_| {
                            format_err!("tag is not compatible with old packet headers: {:?}", tag)
                        })?
                        .with_length_type(typ)
                        .build(),
                    length,
                })
            }
            PacketHeaderVersion::New => {
                ensure!(
                    !matches!(length, PacketLength::Indeterminate),
                    "indeterminate packet length is only supported in old style headers"
                );
                if let PacketLength::Partial(l) = length {
                    ensure!(l.count_ones() == 1, "partial length must be a power of two");
                    ensure!(
                        l <= MAX_PARTIAL_LEN,
                        "partial length must be less or equal than {}",
                        MAX_PARTIAL_LEN
                    );
                }

                Ok(Self::New {
                    header: NewPacketHeaderBuilder::new().with_tag(tag.into()).build(),
                    length,
                })
            }
        }
    }

    /// Returns the packet header version.
    pub const fn version(&self) -> PacketHeaderVersion {
        match self {
            Self::Old { .. } => PacketHeaderVersion::Old,
            Self::New { .. } => PacketHeaderVersion::New,
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

    /// Creates a `New` style packet header.
    pub fn new_fixed(tag: Tag, length: usize) -> Self {
        let header = NewPacketHeaderBuilder::new().with_tag(tag.into()).build();
        PacketHeader::New {
            header,
            length: PacketLength::Fixed(length),
        }
    }
}

impl Serialize for PacketHeader {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        debug!("writing packet header {:?}", self);

        match self {
            Self::New { header, length } => match length {
                PacketLength::Fixed(len) => {
                    writer.write_u8(header.into_bits())?;
                    if *len < 192 {
                        writer.write_u8(*len as u8)?;
                    } else if *len < 8384 {
                        writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                        writer.write_u8(((len - 192) & 0xFF) as u8)?;
                    } else {
                        writer.write_u8(255)?;
                        writer.write_u32::<BigEndian>(*len as u32)?;
                    }
                }
                PacketLength::Indeterminate => {
                    unreachable!(
                        "invalid state: indeterminate lengths for new style packet header"
                    );
                }
                PacketLength::Partial(len) => {
                    writer.write_u8(header.into_bits())?;
                    debug_assert_eq!(len.count_ones(), 1); // must be a power of two

                    // y & 0x1F
                    let n = len.trailing_zeros();
                    let n = (224 + n) as u8;
                    writer.write_u8(n)?;
                }
            },
            Self::Old { header, length } => match length {
                PacketLength::Fixed(len) => {
                    writer.write_u8(header.into_bits())?;
                    if *len < 256 {
                        // one octet
                        writer.write_u8(*len as u8)?;
                    } else if *len < 65536 {
                        // two octets
                        writer.write_u16::<BigEndian>(*len as u16)?;
                    } else {
                        // four octets
                        writer.write_u32::<BigEndian>(*len as u32)?;
                    }
                }
                PacketLength::Indeterminate => {
                    writer.write_u8(header.into_bits())?;
                }
                PacketLength::Partial(_) => {
                    unreachable!("invalid state: partial lengths for old style packet header");
                }
            },
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Self::New { header: _, length } => match length {
                PacketLength::Fixed(len) => {
                    let mut sum = 1; // header
                    if *len < 192 {
                        sum += 1;
                    } else if *len < 8384 {
                        sum += 2;
                    } else {
                        sum += 5
                    }
                    sum
                }
                PacketLength::Indeterminate => {
                    unreachable!(
                        "invalid state: indeterminate lengths for new style packet header"
                    );
                }
                PacketLength::Partial(_len) => 1 + 1,
            },
            Self::Old { header: _, length } => match length {
                PacketLength::Fixed(len) => {
                    let mut sum = 1; // header
                    if *len < 256 {
                        // one octet
                        sum += 1;
                    } else if *len < 65536 {
                        // two octets
                        sum += 2;
                    } else {
                        // four octets
                        sum += 4;
                    }
                    sum
                }
                PacketLength::Indeterminate => 1,
                PacketLength::Partial(_) => {
                    unreachable!("invalid state: partial lengths for old style packet header");
                }
            },
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

fn old_fixed_type(len: usize) -> u8 {
    if len < 256 {
        0
    } else if len < 65536 {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_packet_length() {
        // # off=5053201 ctb=d1 tag=17 hlen=6 plen=4973 new-ctb
        // :attribute packet: [jpeg image of size 4951]
        let packet_header_raw = hex::decode(b"d1ff0000136d").unwrap();
        let header = PacketHeader::from_buf(&mut &packet_header_raw[..]).unwrap();
        dbg!(&header);

        assert_eq!(header.version(), PacketHeaderVersion::New);
        assert_eq!(header.tag(), Tag::UserAttribute);
        assert_eq!(header.packet_length(), PacketLength::Fixed(4973));
    }

    impl Arbitrary for OldPacketHeader {
        type Parameters = u8; // length type
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary() -> Self::Strategy {
            prop::bits::u8::masked(0b0000_0011)
                .prop_flat_map(Self::arbitrary_with)
                .boxed()
        }

        fn arbitrary_with(typ: Self::Parameters) -> Self::Strategy {
            any::<Tag>()
                .prop_map(move |tag| {
                    OldPacketHeaderBuilder::new()
                        .with_tag(tag.into())
                        .with_length_type(typ)
                        .build()
                })
                .boxed()
        }
    }

    impl Arbitrary for NewPacketHeader {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<Tag>()
                .prop_map(|tag| NewPacketHeaderBuilder::new().with_tag(tag.into()).build())
                .boxed()
        }
    }

    impl Arbitrary for PacketHeader {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<PacketLength>()
                .prop_flat_map(|length| match length {
                    PacketLength::Fixed(len) => {
                        assert!(len != 0);
                        prop_oneof![
                            any_with::<OldPacketHeader>(old_fixed_type(len))
                                .prop_map(move |header| PacketHeader::Old { header, length }),
                            any::<NewPacketHeader>()
                                .prop_map(move |header| PacketHeader::New { header, length })
                        ]
                        .boxed()
                    }
                    PacketLength::Indeterminate => any_with::<OldPacketHeader>(3)
                        .prop_map(move |header| PacketHeader::Old { header, length })
                        .boxed(),

                    PacketLength::Partial(_) => any::<NewPacketHeader>()
                        .prop_map(move |header| PacketHeader::New { header, length })
                        .boxed(),
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn write_len(header: PacketHeader) {
            let mut buf = Vec::new();
            header.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), header.write_len());
        }

        #[test]
        fn packet_roundtrip(header: PacketHeader) {
            let mut buf = Vec::new();
            header.to_writer(&mut buf).unwrap();
            let new_header = PacketHeader::from_buf(&mut &buf[..]).unwrap();
            prop_assert_eq!(header, new_header);
        }

        #[test]
        fn packet_header_from_parts(version: PacketHeaderVersion, tag: Tag, len in 1usize..100000) {
            let maybe_header = PacketHeader::from_parts(version, tag, PacketLength::Fixed(len));
            if u8::from(tag) > 16 && version == PacketHeaderVersion::Old {
                prop_assert!(maybe_header.is_err());
            } else {
                let header = maybe_header.unwrap();
                prop_assert_eq!(header.tag(), tag);
                prop_assert_eq!(header.packet_length(), PacketLength::Fixed(len));
                prop_assert_eq!(header.version(), version);
            }
        }
    }
}
