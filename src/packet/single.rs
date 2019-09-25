// comes from inside somewhere of nom
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_let_if_seq))]

use nom::{self, be_u32, be_u8, Err, IResult};
use num_traits::FromPrimitive;

use de::Deserialize;
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

// Parses an old format packet header
// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
#[rustfmt::skip]
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
    >> ({ info!("old {:?} {:?} {:?}", ver, tag, len); (ver, tag, len)})
)));

#[rustfmt::skip]
named!(read_packet_len(&[u8]) -> PacketLength, do_parse!(
       olen: be_u8
    >>  len: switch!(value!(olen),
               // One-Octet Lengths
               0..=191   => value!((olen as usize).into()) |
               // Two-Octet Lengths
               192..=223 => map!(be_u8, |a| {
                   (((olen as usize - 192) << 8) + 192 + a as usize).into()
               }) |
               // Partial Body Lengths
               224..=254 => value!(PacketLength::Partial(1 << (olen as usize & 0x1F))) |
               // Five-Octet Lengths
               255       => map!(be_u32, |v| u32_as_usize(v).into())
    )
    >> (len)
));

fn read_partial_bodies<'a>(input: &'a [u8], len: usize) -> IResult<&'a [u8], ParseResult<'a>> {
    if input.len() < len {
        return Err(Err::Incomplete(nom::Needed::Size(len - input.len())));
    }

    let mut out = Vec::new();
    out.push(&input[0..len]);

    let mut rest = &input[len..];

    loop {
        let res = read_packet_len(rest)?;
        match res.1 {
            PacketLength::Partial(len) => {
                if res.0.len() < len {
                    return Err(Err::Incomplete(nom::Needed::Size(len - res.0.len())));
                }
                out.push(&res.0[0..len]);
                rest = &res.0[len..];
            }
            PacketLength::Fixed(len) => {
                if res.0.len() < len {
                    return Err(Err::Incomplete(nom::Needed::Size(len - res.0.len())));
                }

                out.push(&res.0[0..len]);
                rest = &res.0[len..];
                // this is the last one
                break;
            }
            PacketLength::Indeterminated => {
                // this should not happen, as this is a new style
                // packet, but lets handle it anyway
                out.push(res.0);
                rest = &[];

                // we read everything
                break;
            }
        }
    }

    Ok((rest, ParseResult::Partial(out)))
}

// Parses a new format packet header
// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
#[rustfmt::skip]
named!(new_packet_header(&[u8]) -> (Version, Tag, PacketLength), bits!(do_parse!(
    // First bit is always 1
             tag_bits!(u8, 1, 1)
    // Version: 1
    >>  ver: map_opt!(tag_bits!(u8, 1, 1), Version::from_u8)
    // Packet Tag
    >>  tag: map_opt!(take_bits!(u8, 6), Tag::from_u8)
    >> len: bytes!(read_packet_len)
    >> ({
        info!("new {:?} {:?} {:?}", ver, tag, len);
        (ver, tag, len)
    })
)));

#[derive(Debug)]
pub enum ParseResult<'a> {
    Fixed(&'a [u8]),
    Indeterminated,
    Partial(Vec<&'a [u8]>),
}

// Parse a single Packet
// https://tools.ietf.org/html/rfc4880.html#section-4.2
#[rustfmt::skip]
named!(pub parser<(Version, Tag, PacketLength, ParseResult)>, do_parse!(
       head: alt!(new_packet_header | old_packet_header)
    >> body: switch!(value!(&head.2),
        PacketLength::Fixed(length)   => map!(take!(*length), |v| ParseResult::Fixed(v)) |
        PacketLength::Indeterminated  => value!(ParseResult::Indeterminated) |
        PacketLength::Partial(length) => call!(read_partial_bodies, *length)
    )
    >> (head.0, head.1, head.2, body)
));

pub fn body_parser(ver: Version, tag: Tag, body: &[u8]) -> Result<Packet> {
    info!("packet body: {}", hex::encode(body));
    let res: Result<Packet> = match tag {
        Tag::PublicKeyEncryptedSessionKey => {
            PublicKeyEncryptedSessionKey::from_slice(ver, body).map(Into::into)
        }
        Tag::Signature => Signature::from_slice(ver, body).map(Into::into),
        Tag::SymKeyEncryptedSessionKey => {
            SymKeyEncryptedSessionKey::from_slice(ver, body).map(Into::into)
        }
        Tag::OnePassSignature => OnePassSignature::from_slice(ver, body).map(Into::into),
        Tag::SecretKey => SecretKey::from_slice(ver, body).map(Into::into),
        Tag::PublicKey => PublicKey::from_slice(ver, body).map(Into::into),
        Tag::SecretSubkey => SecretSubkey::from_slice(ver, body).map(Into::into),
        Tag::CompressedData => CompressedData::from_slice(ver, body).map(Into::into),
        Tag::SymEncryptedData => SymEncryptedData::from_slice(ver, body).map(Into::into),
        Tag::Marker => Marker::from_slice(ver, body).map(Into::into),
        Tag::LiteralData => LiteralData::from_slice(ver, body).map(Into::into),
        Tag::Trust => Trust::from_slice(ver, body).map(Into::into),
        Tag::UserId => UserId::from_slice(ver, body).map(Into::into),
        Tag::PublicSubkey => PublicSubkey::from_slice(ver, body).map(Into::into),
        Tag::UserAttribute => UserAttribute::from_slice(ver, body).map(Into::into),
        Tag::SymEncryptedProtectedData => {
            SymEncryptedProtectedData::from_slice(ver, body).map(Into::into)
        }
        Tag::ModDetectionCode => ModDetectionCode::from_slice(ver, body).map(Into::into),
    };

    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            warn!("invalid packet: {:?} {:?}\n{}", err, tag, hex::encode(body));
            Err(Error::InvalidPacketContent(Box::new(err)))
        }
    }
}
