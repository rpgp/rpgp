use std::io;

use nom::{number::streaming::be_u8, IResult};
use num_traits::FromPrimitive;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::*;
use crate::packet::signature::SignatureType;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{KeyId, Tag, Version};

/// One-Pass Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnePassSignature {
    packet_version: Version,
    version: u8,
    typ: SignatureType,
    hash_algorithm: HashAlgorithm,
    pub_algorithm: PublicKeyAlgorithm,
    key_id: KeyId,
    last: u8,
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

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

#[rustfmt::skip]
fn parse(input: &[u8], packet_version: Version) -> IResult<&[u8], OnePassSignature, Error> {
    do_parse!(input,
         version: be_u8
    >>       typ: map_opt!(be_u8, SignatureType::from_u8)
    >>      hash: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>   pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>    key_id: map_res!(take!(8), KeyId::from_slice)
    >> last: be_u8
    >> (OnePassSignature {
        packet_version,
        version,
        typ,
        hash_algorithm: hash,
        pub_algorithm: pub_alg,
        key_id,
        last,
    }))
}

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            self.version,
            self.typ as u8,
            self.hash_algorithm as u8,
            self.pub_algorithm as u8,
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
