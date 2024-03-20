use std::{fmt, io};

use chrono::{SubsecRound, Utc};

use byteorder::{LittleEndian, WriteBytesExt};
use nom::bytes::streaming::take;
use nom::combinator::{map, map_parser, rest};
use nom::multi::length_data;
use nom::number::streaming::{be_u8, le_u16};
use nom::sequence::pair;

use crate::errors::{IResult, Result};
use crate::packet::{PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket};
use crate::ser::Serialize;
use crate::types::{SecretKeyTrait, SignedUserAttribute, Tag, Version};
use crate::util::{packet_length, write_packet_length};

use super::SubpacketData;

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq)]
pub enum UserAttribute {
    Image {
        packet_version: Version,
        header: Vec<u8>,
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
        let (_, pk) = parse(packet_version)(input)?;

        Ok(pk)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttribute::Image { .. } => 1,
            UserAttribute::Unknown { typ, .. } => typ,
        }
    }

    pub fn packet_len(&self) -> usize {
        match self {
            UserAttribute::Image { ref data, .. } => {
                // typ + image header + data length
                1 + 16 + data.len()
            }
            UserAttribute::Unknown { ref data, .. } => {
                // typ + data length
                1 + data.len()
            }
        }
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUserAttribute>
    where
        F: FnOnce() -> String,
    {
        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::CertGeneric)
            .pub_alg(key.algorithm())
            .hash_alg(key.hash_alg())
            .hashed_subpackets(vec![Subpacket::regular(
                SubpacketData::SignatureCreationTime(Utc::now().trunc_subsecs(0)),
            )])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                key.key_id(),
            ))])
            .build()?;

        let sig = config.sign_certification(key, key_pw, self.tag(), &self)?;

        Ok(SignedUserAttribute::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUserAttribute {
        SignedUserAttribute::new(self, vec![sig])
    }
}

impl fmt::Display for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserAttribute::Image { data, .. } => {
                write!(f, "User Attribute: Image (len: {})", data.len())
            }
            UserAttribute::Unknown { typ, data, .. } => {
                write!(f, "User Attribute: typ: {} (len: {})", typ, data.len())
            }
        }
    }
}

fn image(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], UserAttribute> {
    move |i: &[u8]| {
        map(
            pair(
                // little endian, for historical reasons..
                length_data(map(le_u16, |l| l - 2)),
                // the actual image is the rest
                rest,
            ),
            |(header, img): (&[u8], &[u8])| UserAttribute::Image {
                packet_version,
                header: header.to_vec(),
                data: img.to_vec(),
            },
        )(i)
    }
}

fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], UserAttribute> {
    move |i: &[u8]| {
        let (i, len) = packet_length(i)?;
        let (i, typ) = be_u8(i)?;
        let (i, attr) = map_parser(take(len - 1), |i| match typ {
            1 => image(packet_version)(i),
            _ => map(rest, |data: &[u8]| UserAttribute::Unknown {
                packet_version,
                typ,
                data: data.to_vec(),
            })(i),
        })(i)?;
        Ok((i, {
            debug!("attr with len {}", len);
            attr
        }))
    }
}

impl Serialize for UserAttribute {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        debug!("write_packet_len {}", self.packet_len());
        write_packet_length(self.packet_len(), writer)?;

        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ..
            } => {
                // typ: image
                writer.write_all(&[0x01])?;
                writer.write_u16::<LittleEndian>((header.len() + 2) as u16)?;
                writer.write_all(header)?;

                // actual data
                writer.write_all(data)?;
            }
            UserAttribute::Unknown { ref data, typ, .. } => {
                writer.write_all(&[*typ])?;
                writer.write_all(data)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserAttribute::Image {
                ref header,
                ref data,
                ..
            } => f
                .debug_struct("UserAttribute::Image")
                .field("header", &hex::encode(header))
                .field("data", &hex::encode(data))
                .finish(),
            UserAttribute::Unknown { typ, ref data, .. } => f
                .debug_struct("UserAttribute::Image")
                .field("type", &hex::encode([*typ]))
                .field("data", &hex::encode(data))
                .finish(),
        }
    }
}

impl PacketTrait for UserAttribute {
    fn packet_version(&self) -> Version {
        match self {
            UserAttribute::Image { packet_version, .. } => *packet_version,
            UserAttribute::Unknown { packet_version, .. } => *packet_version,
        }
    }

    fn tag(&self) -> Tag {
        Tag::UserAttribute
    }
}
