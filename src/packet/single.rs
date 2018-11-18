use nom::rest;
use num_traits::FromPrimitive;

use errors::{Error, Result};
use packet::packet_sum::Packet;
use packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use types::{PacketLength, Tag, Version};
use util::{u16_as_usize, u32_as_usize, u8_as_usize};

/// Parses an old format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
named!(old_packet_header(&[u8]) -> (Version, Tag, PacketLength), bits!(do_parse!(
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
        0 => map!(take_bits!(u8, 8), |val| u8_as_usize(val).into())    |
        // Two-Octet Lengths
        1 => map!(take_bits!(u16, 16), |val| u16_as_usize(val).into()) |
        // Four-Octet Lengths
        2 => map!(take_bits!(u32, 32), |val| u32_as_usize(val).into()) |
        3 => value!(PacketLength::Indeterminated)
    )
    >> ({ info!("new {:?} {:?} {:?}", ver, tag, len); (ver, tag, len)})
)));

/// Parses a new format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
named!(new_packet_header(&[u8]) -> (Version, Tag, PacketLength), bits!(do_parse!(
    // First bit is always 1
             tag_bits!(u8, 1, 1)
    // Version: 1
    >>  ver: map_opt!(tag_bits!(u8, 1, 1), Version::from_u8)
    // Packet Tag
    >>  tag: map_opt!(take_bits!(u8, 6), Tag::from_u8)
    >> olen: take_bits!(u8, 8)
    >>  len: switch!(value!(olen),
        // One-Octet Lengths
        0...191   => value!((olen as usize).into()) |
        // Two-Octet Lengths
        192...223 => map!(take_bits!(u8, 8), |a| {
            (((olen as usize - 192) << 8) + 192 + a as usize).into()
        }) |
        // Partial Body Lengths
        224...254 => map!(take_bits!(u8, 8), |_| unimplemented!("partial body lengths")) |
        // Five-Octet Lengths
        255       => map!(take_bits!(u32, 32), |v| u32_as_usize(v).into())
    )
    >> ({ info!("new {:?} {:?} {:?}", ver, tag, len); (ver, tag, len)})
)));

/// Parse a single Packet
/// https://tools.ietf.org/html/rfc4880.html#section-4.2
#[rustfmt::skip]
named!(inner_parser<(Tag, &[u8])>, do_parse!(
       head: alt!(new_packet_header | old_packet_header)
    >> body: switch!(value!(head.2),
        PacketLength::Fixed(length) => take!(length) |
        PacketLength::Indeterminated => call!(rest)
    )
    >> (head.1, body)
));

/// Parses a single packet.
pub fn parser<'a>(input: &'a [u8]) -> Result<(&'a [u8], Result<Packet>)> {
    info!("parsing packet ({})", input.len());
    let (rest, (tag, body)) = inner_parser(input)?;

    let res: Result<Packet> = match tag {
        Tag::PublicKeyEncryptedSessionKey => {
            PublicKeyEncryptedSessionKey::from_slice(body).map(|r| r.into())
        }
        Tag::Signature => Signature::from_slice(body).map(|r| r.into()),
        Tag::SymKeyEncryptedSessionKey => {
            SymKeyEncryptedSessionKey::from_slice(body).map(|r| r.into())
        }
        Tag::OnePassSignature => OnePassSignature::from_slice(body).map(|r| r.into()),
        Tag::SecretKey => SecretKey::from_slice(body).map(|r| r.into()),
        Tag::PublicKey => PublicKey::from_slice(body).map(|r| r.into()),
        Tag::SecretSubkey => SecretSubkey::from_slice(body).map(|r| r.into()),
        Tag::CompressedData => CompressedData::from_slice(body).map(|r| r.into()),
        Tag::SymEncryptedData => SymEncryptedData::from_slice(body).map(|r| r.into()),
        Tag::Marker => Marker::from_slice(body).map(|r| r.into()),
        Tag::LiteralData => LiteralData::from_slice(body).map(|r| r.into()),
        Tag::Trust => Trust::from_slice(body).map(|r| r.into()),
        Tag::UserId => UserId::from_slice(body).map(|r| r.into()),
        Tag::PublicSubkey => PublicSubkey::from_slice(body).map(|r| r.into()),
        Tag::UserAttribute => UserAttribute::from_slice(body).map(|r| r.into()),
        Tag::SymEncryptedProtectedData => {
            SymEncryptedProtectedData::from_slice(body).map(|r| r.into())
        }
        Tag::ModDetectionCode => ModDetectionCode::from_slice(body).map(|r| r.into()),
    };

    match res {
        Ok(res) => Ok((rest, Ok(res))),
        Err(err) => Ok((rest, Err(Error::InvalidPacketContent(Box::new(err))))),
    }
}
