use std::io;

use nom::{be_u8, rest};
use num_traits::FromPrimitive;

use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{s2k_parser, KeyId, StringToKey, Tag, Version};

/// Symmetric-Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymKeyEncryptedSessionKey {
    packet_version: Version,
    version: u8,
    sym_algorithm: SymmetricKeyAlgorithm,
    s2k: StringToKey,
    encrypted_key: Option<Vec<u8>>,
}

impl SymKeyEncryptedSessionKey {
    /// Parses a `SymKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, version)?;

        ensure!(
            pk.version == 0x04 || pk.version == 0x05,
            "Version 4 and 5 are the only known version"
        );

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

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

#[rustfmt::skip]
named_args!(parse(packet_version: Version) <SymKeyEncryptedSessionKey>, do_parse!(
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
            packet_version,
            version,
            sym_algorithm: sym_alg,
            s2k,
            encrypted_key,
        }
    })
));

impl Serialize for SymKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!()
    }
}

impl PacketTrait for SymKeyEncryptedSessionKey {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::SymKeyEncryptedSessionKey
    }
}
