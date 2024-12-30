use std::io;

use bstr::{BStr, BString};
use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::errors::Result;
use crate::line_writer::LineBreak;
use crate::normalize_lines::Normalized;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Literal Data Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-literal-data-packet-type-id>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct LiteralData {
    packet_version: Version,
    mode: DataMode,
    /// The filename, may contain non utf-8 bytes
    file_name: BString,
    created: DateTime<Utc>,
    /// Raw data, stored normalized to CRLF line endings, to make signing and verification
    /// simpler.
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',

    #[num_enum(catch_all)]
    Other(u8),
}

impl LiteralData {
    /// Creates a literal data packet from the given string. Normalizes line endings.
    pub fn from_str(file_name: impl Into<BString>, raw_data: &str) -> Self {
        let data = Normalized::new(raw_data.bytes(), LineBreak::Crlf).collect();

        LiteralData {
            packet_version: Version::New,
            mode: DataMode::Utf8,
            file_name: file_name.into(),
            created: Utc::now().trunc_subsecs(0),
            data,
        }
    }

    /// Creates a literal data packet from the given bytes.
    pub fn from_bytes(file_name: &BStr, data: &[u8]) -> Self {
        LiteralData {
            packet_version: Version::New,
            mode: DataMode::Binary,
            file_name: file_name.to_owned(),
            created: Utc::now().trunc_subsecs(0),
            data: data.to_vec().into(),
        }
    }

    /// Parses a `LiteralData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        Self::from_buf(packet_version, input)
    }

    /// Parses a `LiteralData` packet from the given buf.
    pub fn from_buf<B: Buf>(packet_version: Version, mut data: B) -> Result<Self> {
        ensure!(data.remaining() > 2, "invalid literal data packet");

        // Mode
        let mode = DataMode::from(data.get_u8());

        // Name
        let name_len = data.get_u8() as usize;
        ensure!(data.remaining() >= name_len, "invalid literal data packet");
        let mut name_vec = vec![0u8; name_len];
        data.copy_to_slice(&mut name_vec);
        let name = BString::new(name_vec);

        // Created
        ensure!(data.remaining() >= 4, "invalid literal data packet");
        let created = Utc
            .timestamp_opt(i64::from(data.get_u32()), 0)
            .single()
            .ok_or_else(|| format_err!("invalid created field"))?;

        Ok(LiteralData {
            packet_version,
            mode,
            created,
            file_name: name.to_owned(),
            data: data.copy_to_bytes(data.remaining()),
        })
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.mode, DataMode::Binary)
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
        match self.mode {
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
        match self.mode {
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

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = &self.file_name;
        writer.write_u8(self.mode.into())?;
        writer.write_u8(name.len().try_into()?)?;
        writer.write_all(name)?;
        writer.write_u32::<BigEndian>(self.created.timestamp().try_into()?)?;

        // Line endings are stored internally normalized, so we do not need to worry
        // about changing them here.
        writer.write_all(&self.data)?;

        Ok(())
    }
}

impl PacketTrait for LiteralData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::LiteralData
    }
}

#[test]
fn test_utf8_literal() {
    #![allow(clippy::unwrap_used)]

    let slogan = "一门赋予每个人构建可靠且高效软件能力的语言。";
    let literal = LiteralData::from_str("", slogan);
    assert!(std::str::from_utf8(&literal.data).unwrap() == slogan);
}
