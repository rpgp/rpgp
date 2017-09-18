use nom::{be_u8, rest};

use packet::types::UserAttributeType;
use util::packet_length;

named!(image<UserAttributeType>, do_parse!(
    // header length, should be 0x1000
       tag!(&[0x10, 0x00][..])
    // version, only 1 is defined
    >> tag!(&[0x01][..])
    // format, only jpg is defined as 1
    >> tag!(&[0x01][..])
    // 12 reserved octets of 0
    >> tag!(&[0; 12][..])
    // the actual image is the rest
    >> img: rest
    >> (UserAttributeType::Image(img.to_vec()))
));

/// Parse a user attribute packet (Tag 17)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.12
named!(pub parser<UserAttributeType>, do_parse!(
        len: packet_length
    >>  typ: be_u8
    >> attr: flat_map!(
        take!(len - 1),
        switch!(value!(typ),
            1 => call!(image)
        ))
    >> (attr)
));
