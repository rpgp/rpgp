use std::io;

use nom::combinator::{map, rest};
use nom::number::streaming::be_u8;
use nom::sequence::tuple;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
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
        let (_, pk) = parse(version)(input)?;

        if pk.version != 4 && pk.version != 5 {
            unsupported_err!("unsupported SKESK version {}", pk.version);
        }

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
            s2k.uses_salt(),
            "Can not use an s2k algorithm without a salt: {:?}",
            s2k
        );

        let key = s2k.derive_key(&msg_pw(), alg.key_size())?;

        let mut private_key = Vec::with_capacity(session_key.len());
        private_key.push(u8::from(alg));
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

fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], SymKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        map(
            tuple((
                be_u8,
                map(be_u8, SymmetricKeyAlgorithm::from),
                s2k_parser,
                rest,
            )),
            |(version, sym_alg, s2k, encrypted_key)| {
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
            },
        )(i)
    }
}

impl Serialize for SymKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.version, u8::from(self.sym_algorithm)])?;
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
