use nom::be_u8;
use num_traits::FromPrimitive;

use crypto::hash::HashAlgorithm;
use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use packet::signature::SignatureType;
use types::KeyId;

/// One-Pass Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.4
#[derive(Debug, Clone)]
pub struct OnePassSignature {
    version: u8,
    typ: SignatureType,
    hash_algorithm: HashAlgorithm,
    pub_algorithm: PublicKeyAlgorithm,
    key_id: KeyId,
    is_nested: bool,
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }
}

#[rustfmt::skip]
named!(parse<OnePassSignature>, do_parse!(
         version: be_u8
    >>       typ: map_opt!(be_u8, SignatureType::from_u8)
    >>      hash: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>   pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>    key_id: map_res!(take!(8), KeyId::from_slice)
    >> is_nested: map!(be_u8, |v| v > 0)
    >> (OnePassSignature {
        version,
        typ,
        hash_algorithm: hash,
        pub_algorithm: pub_alg,
        key_id,
        is_nested,
    })
));
