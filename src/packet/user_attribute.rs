use nom::{be_u8, le_u16, rest};

use errors::Result;
use types::Version;
use util::packet_length;

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UserAttribute {
    Image {
        packet_version: Version,
        data: Vec<u8>,
    },
    Unknown {
        packet_version: Version,
        typ: u8,
        data: Vec<u8>,
    },
}

impl UserAttribute {
    /// Parses a `UserAttribute` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttribute::Image { .. } => 1,
            UserAttribute::Unknown { typ, .. } => typ,
        }
    }

    pub fn packet_version(&self) -> Version {
        match self {
            UserAttribute::Image { packet_version, .. } => *packet_version,
            UserAttribute::Unknown { packet_version, .. } => *packet_version,
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
named_args!(image(packet_version: Version) <UserAttribute>, do_parse!(
        // header length (should be 0x1000)
        // little endian, for historical reasons..
        header_len: le_u16
    >>     _header: flat_map!(take!(header_len - 2), image_header)
    // TODO: use header information
    // the actual image is the rest
    >>         img: rest
    >> (UserAttribute::Image {
        packet_version,
        data: img.to_vec()
    })
));

#[rustfmt::skip]
named_args!(parse(packet_version: Version) <UserAttribute>, do_parse!(
        len: packet_length
    >>  typ: be_u8
    >> attr: flat_map!(
        take!(len-1),
        switch!(value!(typ),
                1 => call!(image, packet_version) |
                _ => map!(rest, |data| UserAttribute::Unknown {
                    packet_version,
                    typ,
                    data: data.to_vec()
                })
        ))
    >> (attr)
));
