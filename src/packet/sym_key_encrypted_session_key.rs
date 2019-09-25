use std::io;

use nom::{be_u8, rest};
use num_traits::FromPrimitive;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{s2k_parser, StringToKey, Tag, Version};

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

    pub fn sym_algorithm(&self) -> SymmetricKeyAlgorithm {
        self.sym_algorithm
    }

    pub fn s2k(&self) -> &StringToKey {
        &self.s2k
    }

    pub fn encrypted_key(&self) -> &Option<Vec<u8>> {
        &self.encrypted_key
    }

    pub fn encrypt<F>(
        msg_pw: F,
        session_key: &[u8],
        s2k: StringToKey,
        alg: SymmetricKeyAlgorithm,
    ) -> Result<Self>
    where
        F: FnOnce() -> String + Clone,
    {
        ensure!(
            s2k.salt().is_some(),
            "can not use an s2k algorithm without a salt"
        );

        let key = s2k.derive_key(&msg_pw(), alg.key_size())?;

        let mut private_key = Vec::with_capacity(session_key.len());
        private_key.push(alg as u8);
        private_key.extend(session_key);

        let iv = vec![0u8; alg.block_size()];
        let mut encrypted_key = private_key.to_vec();
        alg.encrypt_with_iv_regular(&key, &iv, &mut encrypted_key)?;

        Ok(SymKeyEncryptedSessionKey {
            packet_version: Default::default(),
            version: 0x04,
            s2k,
            sym_algorithm: alg,
            encrypted_key: Some(encrypted_key),
        })
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
        writer.write_all(&[self.version, self.sym_algorithm as u8])?;
        self.s2k.to_writer(writer)?;

        if let Some(ref key) = self.encrypted_key {
            writer.write_all(key)?;
        }

        Ok(())
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
