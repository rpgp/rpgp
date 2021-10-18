use std::{fmt, io};

use byteorder::{BigEndian, WriteBytesExt};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, rest},
    number::streaming::{be_u32, be_u8},
    IResult,
};
use num_traits::FromPrimitive;

use crate::errors::Result;
use crate::line_writer::LineBreak;
use crate::normalize_lines::Normalized;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};
use crate::util::{read_string, write_string};

/// Literal Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.9
#[derive(Clone, PartialEq, Eq)]
pub struct LiteralData {
    packet_version: Version,
    mode: DataMode,
    file_name: String,
    created: DateTime<Utc>,
    /// Raw data, stored normalized to CRLF line endings, to make signing and verification
    /// simpler.
    data: Vec<u8>,
}

#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',
}

impl LiteralData {
    /// Creates a literal data packet from the given string. Normalizes line endings.
    pub fn from_str(file_name: &str, raw_data: &str) -> Self {
        let data = Normalized::new(raw_data.bytes(), LineBreak::Crlf).collect();

        LiteralData {
            packet_version: Version::New,
            mode: DataMode::Utf8,
            file_name: file_name.to_owned(),
            created: Utc::now().trunc_subsecs(0),
            data,
        }
    }

    /// Creates a literal data packet from the given bytes.
    pub fn from_bytes(file_name: &str, data: &[u8]) -> Self {
        LiteralData {
            packet_version: Version::New,
            mode: DataMode::Binary,
            file_name: file_name.to_owned(),
            created: Utc::now().trunc_subsecs(0),
            data: data.to_owned(),
        }
    }

    /// Parses a `LiteralData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.mode, DataMode::Binary)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Convert the data to a UTF-8 string, if appropriate for the type.
    /// Returns `None` if `mode` is `Binary`, or the data is not valid UTF-8.
    pub fn to_string(&self) -> Option<String> {
        match self.mode {
            DataMode::Binary => None,
            _ => std::str::from_utf8(&self.data).map(str::to_owned).ok(),
        }
    }
}

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = write_string(&self.file_name);
        writer.write_all(&[self.mode as u8, name.len() as u8])?;
        writer.write_all(&name)?;
        writer.write_u32::<BigEndian>(self.created.timestamp() as u32)?;

        // Line endings are stored internally normalized, so we do not need to worry
        // about changing them here.
        writer.write_all(&self.data)?;

        Ok(())
    }
}

fn parse(i: &[u8], packet_version: Version) -> IResult<&[u8], LiteralData> {
    let (i, mode) = map_opt(be_u8, DataMode::from_u8)(i)?;
    let (i, name_len) = be_u8(i)?;
    let (i, name) = map(take(name_len), read_string)(i)?;
    let (i, created) = map(be_u32, |v| Utc.timestamp(i64::from(v), 0))(i)?;
    let (i, data) = rest(i)?;

    Ok((
        i,
        LiteralData {
            packet_version,
            mode,
            created,
            file_name: name,
            data: data.to_vec(),
        },
    ))
}

impl PacketTrait for LiteralData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::LiteralData
    }
}

impl fmt::Debug for LiteralData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiteralData")
            .field("packet_version", &self.packet_version)
            .field("mode", &self.mode)
            .field("created", &self.created)
            .field("file_name", &self.file_name)
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}

#[test]
fn test_utf8_literal() {
    let slogan = "一门赋予每个人构建可靠且高效软件能力的语言。";
    let literal = LiteralData::from_str("", &slogan);
    assert!(String::from_utf8(literal.data).unwrap() == slogan);
}
