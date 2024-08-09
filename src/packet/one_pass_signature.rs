use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::number::streaming::be_u8;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::packet::signature::SignatureType;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{KeyId, Tag, Version};

/// One-Pass Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.4
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct OnePassSignature {
    pub packet_version: Version,
    pub typ: SignatureType,
    pub hash_algorithm: HashAlgorithm,
    pub pub_algorithm: PublicKeyAlgorithm,
    pub last: u8,
    pub version_specific: OpsVersionSpecific,
}

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum OpsVersionSpecific {
    V3 {
        key_id: KeyId,
    },
    V6 {
        salt: Vec<u8>,
        fingerprint: [u8; 32],
    },
}

impl OnePassSignature {
    pub fn version(&self) -> u8 {
        match self.version_specific {
            OpsVersionSpecific::V3 { .. } => 3,
            OpsVersionSpecific::V6 { .. } => 6,
        }
    }
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(packet_version)(input)?;

        Ok(pk)
    }

    /// RFC 4880-era OpenPGP uses v3 one pass signature packets (NOTE: there is no v4 OPS)
    ///
    /// "When generating a one-pass signature, the OPS packet version MUST correspond to the
    /// version of the associated Signature packet, except for the historical accident that version
    /// 4 keys use a version 3 One-Pass Signature packet (there is no version 4 OPS)."
    ///
    /// https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t
    pub fn from_details_v3(
        typ: SignatureType,
        hash_algorithm: HashAlgorithm,
        pub_algorithm: PublicKeyAlgorithm,
        key_id: KeyId,
    ) -> Self {
        OnePassSignature {
            packet_version: Default::default(),
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific: OpsVersionSpecific::V3 { key_id },
        }
    }

    /// Version 6 OpenPGP signatures must be combined with v6 one pass signature packets.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t
    pub fn from_details_v6(
        typ: SignatureType,
        hash_algorithm: HashAlgorithm,
        pub_algorithm: PublicKeyAlgorithm,
        salt: Vec<u8>,
        fingerprint: [u8; 32],
    ) -> Self {
        OnePassSignature {
            packet_version: Default::default(),
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific: OpsVersionSpecific::V6 { salt, fingerprint },
        }
    }
}

fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], OnePassSignature> {
    move |i: &[u8]| {
        let (i, version) = be_u8(i)?;
        let (i, typ) = map_res(be_u8, SignatureType::try_from)(i)?;
        let (i, hash_algorithm) = map(be_u8, HashAlgorithm::from)(i)?;
        let (i, pub_algorithm) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

        let (i, version_specific) = match version {
            3 => {
                let (i, key_id) = map_res(take(8usize), KeyId::from_slice)(i)?;

                (i, OpsVersionSpecific::V3 { key_id })
            }
            6 => {
                let (i, salt_len) = be_u8(i)?;
                let (i, salt) = map(take(salt_len), |salt: &[u8]| salt.to_vec())(i)?;
                let (i, fingerprint) = map_res(take(32usize), TryInto::try_into)(i)?;

                (i, OpsVersionSpecific::V6 { salt, fingerprint })
            }
            _ => {
                return Err(nom::Err::Error(crate::errors::Error::Unsupported(format!(
                    "Unsupported one pass signature packet version {version}",
                ))))
            }
        };

        let (i, last) = be_u8(i)?;

        let ops = OnePassSignature {
            packet_version,
            typ,
            hash_algorithm,
            pub_algorithm,
            last,
            version_specific,
        };

        Ok((i, ops))
    }
}

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            self.version(),
            self.typ.into(),
            self.hash_algorithm.into(),
            self.pub_algorithm.into(),
        ])?;

        // salt, if v6
        if let OpsVersionSpecific::V6 { salt, .. } = &self.version_specific {
            let len: u8 = salt.len().try_into()?;
            writer.write_all(&[len])?;
            writer.write_all(salt)?;
        }

        match &self.version_specific {
            OpsVersionSpecific::V3 { key_id } => {
                writer.write_all(key_id.as_ref())?;
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                writer.write_all(fingerprint.as_ref())?;
            }
        }
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
