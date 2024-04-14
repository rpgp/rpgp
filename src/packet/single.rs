// comes from inside somewhere of nom
#![allow(clippy::useless_let_if_seq)]

use nom::bits;
use nom::branch::alt;
use nom::combinator::{map, map_res};
use nom::number::streaming::{be_u32, be_u8};
use nom::sequence::{preceded, tuple};

use crate::de::Deserialize;
use crate::errors::{Error, IResult, Result};
use crate::packet::packet_sum::Packet;
use crate::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, Padding, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use crate::types::{PacketLength, Tag, Version};
use crate::util::{u16_as_usize, u32_as_usize, u8_as_usize};

/// Parses an old format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
fn old_packet_header(i: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength)> {
    #[allow(non_snake_case)]
    bits::bits::<_, _, crate::errors::Error, _, _>(|I| {
        use bits::streaming::{tag, take};
        let (I, (_, ver, tag, len_type)) = tuple((
            // First bit is always 1
            tag(0b1, 1usize),
            // Version: 0
            map_res(tag(0b0, 1usize), Version::try_from),
            // Packet Tag
            map_res(take(4usize), u8::try_into),
            // Packet Length Type
            take(2usize),
        ))(I)?;
        let (I, len) = match len_type {
            // One-Octet Lengths
            0 => map(take(8usize), |val| u8_as_usize(val).into())(I)?,
            // Two-Octet Lengths
            1 => map(take(16usize), |val| u16_as_usize(val).into())(I)?,
            // Four-Octet Lengths
            2 => map(take(32usize), |val| u32_as_usize(val).into())(I)?,
            3 => (I, PacketLength::Indeterminate),
            _ => {
                return Err(nom::Err::Error(crate::errors::Error::ParsingError(
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((I, (ver, tag, len)))
    })(i)
}

pub(crate) fn read_packet_len(i: &[u8]) -> IResult<&[u8], PacketLength> {
    let (i, olen) = be_u8(i)?;
    match olen {
        // One-Octet Lengths
        0..=191 => Ok((i, (olen as usize).into())),
        // Two-Octet Lengths
        192..=223 => map(be_u8, |a| {
            (((olen as usize - 192) << 8) + 192 + a as usize).into()
        })(i),
        // Partial Body Lengths
        224..=254 => Ok((i, PacketLength::Partial(1 << (olen as usize & 0x1F)))),
        // Five-Octet Lengths
        255 => {
            let (i, len) = be_u32(i)?;
            Ok((i, (len as usize).into()))
        }
    }
}

/// Parses a new format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
fn new_packet_header(i: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength)> {
    use bits::streaming::*;
    #[allow(non_snake_case)]
    bits::bits(|I| {
        preceded(
            // First bit is always 1
            tag(0b1, 1usize),
            tuple((
                // Version: 1
                map_res(tag(0b1, 1usize), Version::try_from),
                // Packet Tag
                map(take(6usize), u8::into),
                // packet length
                bits::bytes(read_packet_len),
            )),
        )(I)
    })(i)
}

/// Parse a single Packet
/// https://tools.ietf.org/html/rfc4880.html#section-4.2
pub fn parser(i: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength)> {
    let (i, head) = alt((new_packet_header, old_packet_header))(i)?;

    Ok((i, head))
}

pub fn body_parser(ver: Version, tag: Tag, body: &[u8]) -> Result<Packet> {
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
        Tag::Padding => Padding::from_slice(ver, body).map(Into::into),
        Tag::Other(other) => unimplemented_err!("Unknown packet typ: {}", other),
    };

    match res {
        Ok(res) => Ok(res),
        Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
        Err(err) => {
            warn!("invalid packet: {:?} {:?}\n{}", err, tag, hex::encode(body));
            Err(Error::InvalidPacketContent(Box::new(err)))
        }
    }
}
