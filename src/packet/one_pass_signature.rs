use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::number::streaming::be_u8;
use nom::sequence::tuple;
use nom::IResult;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::signature::SignatureType;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{KeyId, Tag, Version};

/// One-Pass Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnePassSignature {
    pub packet_version: Version,
    pub version: u8,
    pub typ: SignatureType,
    pub hash_algorithm: HashAlgorithm,
    pub pub_algorithm: PublicKeyAlgorithm,
    pub key_id: KeyId,
    pub last: u8,
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(packet_version)(input)?;

        if pk.version != 2 && pk.version != 3 && pk.version != 4 && pk.version != 5 {
            unsupported_err!("unsupported signature version {}", pk.version);
        }

        Ok(pk)
    }

    pub fn from_details(
        typ: SignatureType,
        hash_algorithm: HashAlgorithm,
        pub_algorithm: PublicKeyAlgorithm,
        key_id: KeyId,
    ) -> Self {
        OnePassSignature {
            packet_version: Default::default(),
            version: 0x03,
            typ,
            hash_algorithm,
            pub_algorithm,
            key_id,
            last: 1,
        }
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], OnePassSignature> {
    move |i: &[u8]| {
        map(
            tuple((
                be_u8,
                map_res(be_u8, SignatureType::try_from),
                map(be_u8, HashAlgorithm::from),
                map(be_u8, PublicKeyAlgorithm::from),
                map_res(take(8usize), KeyId::from_slice),
                be_u8,
            )),
            |(version, typ, hash, pub_alg, key_id, last)| OnePassSignature {
                packet_version,
                version,
                typ,
                hash_algorithm: hash,
                pub_algorithm: pub_alg,
                key_id,
                last,
            },
        )(i)
    }
}

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            self.version,
            self.typ as u8,
            self.hash_algorithm.into(),
            self.pub_algorithm.into(),
        ])?;
        writer.write_all(self.key_id.as_ref())?;
        writer.write_all(&[self.last])?;

        Ok(())
    }
}

impl PacketTrait for OnePassSignature {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::OnePassSignature
    }
}
