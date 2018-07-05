use enum_primitive::FromPrimitive;
use util::{u16_as_usize, u32_as_usize, u8_as_usize};

use super::types::{Packet, Tag, Version};

/// Parses an old format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
named!(old_packet_header(&[u8]) -> (Version, Tag, usize), bits!(do_parse!(
    // First bit is always 1
            tag_bits!(u8, 1, 1)
    // Version: 0
    >> ver: map_opt!(tag_bits!(u8, 1, 0), Version::from_u8)
    // Packet Tag
    >> tag: map_opt!(take_bits!(u8, 4), Tag::from_u8)
    // Packet Length Type
    >> len_type: take_bits!(u8, 2)
    >> len: switch!(value!(len_type),
        // One-Octet Lengths
        0 => map!(take_bits!(u8, 8), u8_as_usize)    |
        // Two-Octet Lengths
        1 => map!(take_bits!(u16, 16), u16_as_usize) |
        // Four-Octet Lengths
        2 => map!(take_bits!(u32, 32), u32_as_usize)
        // TODO: Indeterminate length
        // 3 => unimplemented!("indeterminate length")
    )
        >> (ver, tag, len)
)));

/// Parses a new format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
named!(new_packet_header(&[u8]) -> (Version, Tag, usize), bits!(do_parse!(
    // First bit is always 1
             tag_bits!(u8, 1, 1)
    // Version: 1
    >>  ver: map_opt!(tag_bits!(u8, 1, 1), Version::from_u8)
    // Packet Tag
    >>  tag: map_opt!(take_bits!(u8, 6), Tag::from_u8)
    >> olen: take_bits!(u8, 8)
    >>  len: switch!(value!(olen),
        // One-Octet Lengths
        0...191   => value!(olen as usize) |
        // Two-Octet Lengths
        192...254 => map!(take_bits!(u8, 8), |a| {
            ((olen as usize - 192) << 8) + 192 + a as usize
        }) |
        // Five-Octet Lengths
        255       => map!(take_bits!(u32, 32), u32_as_usize)
        // Partial Body Lengths
        // TODO: 224...254 => value!(1)
    )
    >> (ver, tag, len)
)));

/// Parse Packet Headers
/// ref: https://tools.ietf.org/html/rfc4880.html#section-4.2
named!(pub parser<Packet>, do_parse!(
       head: alt!(new_packet_header | old_packet_header)
    >> body: take!(head.2)
    >> (Packet{
            version: head.0,
            tag: head.1,
            body: body.to_vec(),
        })
));
