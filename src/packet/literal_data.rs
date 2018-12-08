use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u32, be_u8, rest};
use num_traits::FromPrimitive;

use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{Tag, Version};
use util::{read_string, write_string};

/// Literal Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.9
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralData {
    packet_version: Version,
    mode: DataMode,
    file_name: String,
    created: DateTime<Utc>,
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
    /// Parses a `LiteralData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = write_string(&self.file_name);
        writer.write_all(&[self.mode as u8, name.len() as u8])?;
        writer.write_u32::<BigEndian>(self.created.timestamp() as u32)?;

        match self.mode {
            DataMode::Binary => {
                writer.write_all(&self.data)?;
            }
            _ => unimplemented!("mode: {:?}", self.mode),
        }

        Ok(())
    }
}

#[rustfmt::skip]
named_args!(parse(packet_version: Version)<LiteralData>, do_parse!(
           mode: map_opt!(be_u8, DataMode::from_u8)
    >> name_len: be_u8
    >>     name: map!(take!(name_len), read_string)
    >>  created: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>     data: rest
    >> (LiteralData {
        packet_version,
        mode,
        created,
        file_name: name,
        data: data.to_vec(),
    })
));

impl PacketTrait for LiteralData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::LiteralData
    }
}
