use nom::{be_u8, rest};
use num_traits::FromPrimitive;

use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use types::{s2k_parser, KeyId, StringToKey};

/// Symmetric-Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.3
#[derive(Debug, Clone)]
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

    pub fn id(&self) -> &KeyId {
        // TODO: figure out how, probably need decryption first?
        unimplemented!()
    }

    pub fn mpis(&self) -> &[Vec<u8>] {
        // TODO: figure out how, probably need decryption first?
        unimplemented!()
    }
}

#[rustfmt::skip]
named!(parse<SymKeyEncryptedSessionKey>, do_parse!(
              version: be_u8
    >>        sym_alg: map_opt!(be_u8, SymmetricKeyAlgorithm::from_u8)
    >>            s2k: s2k_parser
    >>  encrypted_key: rest
    >> ({
        let encrypted_key = if encrypted_key.is_empty() {
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
    })
));
