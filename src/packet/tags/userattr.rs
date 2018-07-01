use nom::{be_u8, le_u16, rest};

use packet::types::UserAttributeType;
use util::packet_length;

named!(
    image_header<(u8, u8)>,
    do_parse!(
        // version
        version: be_u8
    // format
    >>   format: switch!(value!(version),
                       1 => call!(be_u8) |
                       _ => value!(0)
    )
    // skip the rest
    >>            rest >> (version, format)
    )
);

named!(
    image<UserAttributeType>,
    do_parse!(
        // header length (should be 0x1000)
        // little endian, for historical reasons..
        header_len: le_u16
    >>     _header: flat_map!(take!(header_len - 2), image_header)
    // TODO: use header information
    // the actual image is the rest
    >>         img: rest >> (UserAttributeType::Image(img.to_vec()))
    )
);

/// Parse a user attribute packet (Tag 17)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.12
named!(pub parser<UserAttributeType>, do_parse!(
        len: packet_length
    >>  typ: be_u8
    >> attr: flat_map!(
        take!(len-1),
        switch!(value!(typ),
                1 => call!(image) |
              _ => map!(rest, |data| UserAttributeType::Unknown((typ, data.to_vec())))
        ))
    >> (attr)
));
