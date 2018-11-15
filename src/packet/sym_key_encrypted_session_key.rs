use nom::{be_u8, rest};
use num_traits::FromPrimitive;

use crypto::sym::SymmetricKeyAlgorithm;
use packet::packet_trait::Packet;
use packet::types::Tag;
use types::{s2k_parser, StringToKey};

/// Symmetric-Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.3
pub struct SymKeyEncryptedSessionKey {
    version: u8,
    sym_algorithm: SymmetricKeyAlgorithm,
    s2k: StringToKey,
    encrypted_key: Option<Vec<u8>>,
}

impl SymKeyEncryptedSessionKey {
    /// Parses a `SymKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        // TODO: openpgpjs has a version 5, investigate!
        ensure_eq!(pk.version, 0x04, "Version 4 is the only known version");

        Ok(pk)
    }
}

impl Packet for SymKeyEncryptedSessionKey {
    fn tag(&self) -> Tag {
        Tag::SymKeyEncryptedSessionKey
    }
}

#[rustfmt::skip]
named!(parse<OnePassSignature>, do_parse!(
              version: be_u8,
    >>        sym_alg: map_res!(be_u8, SymmetricKeyAlgorithm::from_u8)
    >>            s2k: s2k_parser
    >>  encrypted_key: rest
    >> ({
        let encrypted_key = if encrypted_key.len() == 0 {
            None
        } else {
            Some(encrypted_key.to_vec())
        };
        SymKeyEncryptedSessionKey {
            version,
            sym_algorithm: sym_alg,
            s2k,
            encrypted_key,
        }
    )
));
