use nom::{be_u8, le_u16, rest};

use errors::Result;
use util::packet_length;

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UserAttribute {
    Image(Vec<u8>),
    Unknown((u8, Vec<u8>)),
}

impl UserAttribute {
    /// Parses a `UserAttribute` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttribute::Image(_) => 1,
            UserAttribute::Unknown((typ, _)) => typ,
        }
    }
}

#[rustfmt::skip]
named!(image_header<(u8, u8)>, do_parse!(
    // version
        version: be_u8
    // format
    >>   format: switch!(value!(version),
                       1 => call!(be_u8) |
                       _ => value!(0)
    )
    // skip the rest
    >>           rest
    >> (version, format)
));

#[rustfmt::skip]
named!(image<UserAttribute>, do_parse!(
        // header length (should be 0x1000)
        // little endian, for historical reasons..
        header_len: le_u16
    >>     _header: flat_map!(take!(header_len - 2), image_header)
    // TODO: use header information
    // the actual image is the rest
    >>         img: rest
    >> (UserAttribute::Image(img.to_vec()))
));

#[rustfmt::skip]
named!(parse<UserAttribute>, do_parse!(
        len: packet_length
    >>  typ: be_u8
    >> attr: flat_map!(
        take!(len-1),
        switch!(value!(typ),
                1 => call!(image) |
                _ => map!(rest, |data| UserAttribute::Unknown((typ, data.to_vec())))
        ))
    >> (attr)
));
