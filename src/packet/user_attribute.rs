use std::{fmt, io};

use aes_gcm::aead::rand_core::CryptoRng;
use byteorder::{LittleEndian, WriteBytesExt};
use chrono::{SubsecRound, Utc};
use log::debug;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_parser, rest};
use nom::multi::length_data;
use nom::number::streaming::{be_u8, le_u16};
use nom::sequence::pair;
use rand::Rng;

use super::{SignatureVersion, SubpacketData};
use crate::errors::{IResult, Result};
use crate::packet::{PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket};
use crate::ser::Serialize;
use crate::types::{PublicKeyTrait, SecretKeyTrait, SignedUserAttribute, Tag, Version};
use crate::util::{packet_length, write_packet_length};

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum UserAttribute {
    Image {
        packet_version: Version,
        #[debug("{}", hex::encode(header))]
        header: Vec<u8>,
        #[debug("{}", hex::encode(data))]
        data: Vec<u8>,
    },
    Unknown {
        packet_version: Version,
        typ: u8,
        #[debug("{}", hex::encode(data))]
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

    /// Create a self-signature
    pub fn sign<R, F>(
        &self,
        rng: &mut R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        self.sign_third_party(rng, key, key_pw, key)
    }

    /// Create a third-party signature
    pub fn sign_third_party<R, F>(
        &self,
        rng: &mut R,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        let sig_version = signer.version().try_into()?;
        let hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            Utc::now().trunc_subsecs(0),
        ))];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))];

        let config = match sig_version {
            SignatureVersion::V4 => SignatureConfigBuilder::v4()
                .typ(SignatureType::CertGeneric)
                .pub_alg(signer.algorithm())
                .hash_alg(signer.hash_alg())
                .hashed_subpackets(hashed_subpackets)
                .unhashed_subpackets(unhashed_subpackets)
                .build()?,
            SignatureVersion::V6 => SignatureConfigBuilder::v6()
                .typ(SignatureType::CertGeneric)
                .pub_alg(signer.algorithm())
                .hash_alg(signer.hash_alg())
                .hashed_subpackets(hashed_subpackets)
                .unhashed_subpackets(unhashed_subpackets)
                .generate_salt(rng)?
                .build()?,
            _ => unsupported_err!("unsupported signature version: {:?}", sig_version),
        };

        let sig =
            config.sign_certification_third_party(signer, signer_pw, signee, self.tag(), &self)?;

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
