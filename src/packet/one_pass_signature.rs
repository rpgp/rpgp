use std::io;

use nom::be_u8;
use num_traits::FromPrimitive;

use crypto::hash::HashAlgorithm;
use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use packet::signature::SignatureType;
use packet::PacketTrait;
use ser::Serialize;
use types::{KeyId, Tag, Version};

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
    is_nested: bool,
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

#[rustfmt::skip]
named_args!(parse(packet_version: Version) <OnePassSignature>, do_parse!(
         version: be_u8
    >>       typ: map_opt!(be_u8, SignatureType::from_u8)
    >>      hash: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>   pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>    key_id: map_res!(take!(8), KeyId::from_slice)
    >> is_nested: map!(be_u8, |v| v > 0)
    >> (OnePassSignature {
        packet_version,
        version,
        typ,
        hash_algorithm: hash,
        pub_algorithm: pub_alg,
        key_id,
        is_nested,
    })
));

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!()
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
