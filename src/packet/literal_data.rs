use std::str;

use nom::{be_u8, rest};

use packet::packet_trait::Packet;
use packet::types::Tag;

/// Literal Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.9
#[derive(Debug, Clone)]
pub struct LiteralData {
    mode: DataMode,
    file_name: String,
    created: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Debug, Copy, Clone)]
pub enum DataMode {
    Binary,
    Text,
}

impl LiteralData {
    /// Parses a `LiteralData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }
}

impl Packet for LiteralData {
    fn tag(&self) -> Tag {
        Tag::Literal
    }
}

#[rustfmt::skip]
named!(parse<LiteralData>, do_parse!(
           mode: be_u8
    >> name_len: be_u8
    >>     name: map_res!(take!(name_len), str::from_utf8)
    >>  created: take!(4)
    >>     data: rest
    >> (LiteralData {
        mode,
        created: created.to_vec(),
        name: name.to_string(),
        data: data.to_vec(),
    })
));
