use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::errors::Result;
use crate::line_writer::LineBreak;
use crate::normalize_lines::Normalized;
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::Tag;

#[cfg(test)]
use proptest::prelude::*;

/// Literal Data Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-literal-data-packet-type-id>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct LiteralData {
    packet_header: PacketHeader,
    header: LiteralDataHeader,
    /// Raw data, stored normalized to CRLF line endings, to make signing and verification
    /// simpler.
    #[debug("{}", hex::encode(data))]
    #[cfg_attr(
        test,
        proptest(
            strategy = "any::<Vec<u8>>().prop_map(Into::into)",
            filter = "|d| !d.is_empty()"
        )
    )]
    data: Bytes,
}
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct LiteralDataHeader {
    pub mode: DataMode,
    /// The filename, may contain non utf-8 bytes
    pub file_name: Bytes,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))]
    Other(u8),
}

impl LiteralData {
    /// Creates a literal data packet from the given string. Normalizes line endings.
    pub fn from_str(file_name: impl Into<Bytes>, raw_data: &str) -> Self {
        let data: Bytes = Normalized::new(raw_data.bytes(), LineBreak::Crlf).collect();
        let header = LiteralDataHeader {
            mode: DataMode::Utf8,
            file_name: file_name.into(),
            created: Utc::now().trunc_subsecs(0),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);

        LiteralData {
            packet_header,
            header,
            data,
        }
    }

    /// Creates a literal data packet from the given bytes.
    pub fn from_bytes(file_name: impl Into<Bytes>, data: Bytes) -> Self {
        let header = LiteralDataHeader {
            mode: DataMode::Binary,
            file_name: file_name.into(),
            created: Utc::now().trunc_subsecs(0),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);

        LiteralData {
            packet_header,
            header,
            data,
        }
    }

    /// Parses a `LiteralData` packet from the given buf.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        // Mode
        let mode = data.read_u8().map(DataMode::from)?;

        // Name
        let name_len = data.read_u8()?;
        let name = data.read_take(name_len.into())?;

        // Created
        let created = data.read_be_u32()?;
        let created = Utc
            .timestamp_opt(created.into(), 0)
            .single()
            .ok_or_else(|| format_err!("invalid created field"))?;

        let data = data.rest();

        Ok(LiteralData {
            packet_header,
            header: LiteralDataHeader {
                mode,
                created,
                file_name: name,
            },
            data,
        })
    }

    pub fn file_name(&self) -> &Bytes {
        &self.header.file_name
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.header.mode, DataMode::Binary)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    /// Extracts data in to raw data
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    #[inline]
    /// Extracts data as string, returning raw bytes as Err if not valid utf-8 string
    pub fn try_into_string(self) -> Result<String, Bytes> {
        match self.header.mode {
            DataMode::Binary => Err(self.data),
            _ => match std::str::from_utf8(&self.data) {
                Ok(data) => Ok(data.to_string()),
                Err(_error) => Err(self.data),
            },
        }
    }

    /// Convert the data to a UTF-8 string, if appropriate for the type.
    /// Returns `None` if `mode` is `Binary`, or the data is not valid UTF-8.
    pub fn to_string(&self) -> Option<String> {
        match self.header.mode {
            DataMode::Binary => None,
            _ => std::str::from_utf8(&self.data).map(str::to_owned).ok(),
        }
    }
}

impl AsRef<[u8]> for LiteralData {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for LiteralDataHeader {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = &self.file_name;
        writer.write_u8(self.mode.into())?;
        writer.write_u8(name.len().try_into()?)?;
        writer.write_all(name)?;
        writer.write_u32::<BigEndian>(self.created.timestamp().try_into()?)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1 + 1;
        sum += self.file_name.len();
        sum += 4;
        sum
    }
}

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.header.to_writer(writer)?;
        // Line endings are stored internally normalized, so we do not need to worry
        // about changing them here.
        writer.write_all(&self.data)?;

        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = self.header.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for LiteralData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_literal() {
        let slogan = "一门赋予每个人构建可靠且高效软件能力的语言。";
        let literal = LiteralData::from_str("", slogan);
        assert!(std::str::from_utf8(&literal.data).unwrap() == slogan);
    }

    impl Arbitrary for LiteralDataHeader {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<(DataMode, Vec<u8>, u32)>()
                .prop_map(|(mode, file_name, created)| {
                    let created = chrono::Utc
                        .timestamp_opt(created as i64, 0)
                        .single()
                        .expect("invalid time");
                    LiteralDataHeader {
                        mode,
                        file_name: file_name.into(),
                        created,
                    }
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn write_len(packet: LiteralData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(packet: LiteralData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = LiteralData::from_buf(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
