use std::io;

use byteorder::WriteBytesExt;
use bytes::{Buf, Bytes};

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::signature::SignatureType;
use crate::packet::PacketTrait;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{KeyId, Tag, Version};

#[cfg(test)]
use proptest::prelude::*;

/// One-Pass Signature Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t>
///
/// A One-Pass Signature Packet acts as a companion to a Signature Packet. In modern OpenPGP
/// messages, Ops and Signatures occur in pairs, bracketing the message payload.
///
/// The Ops packet contains all the information that a recipient needs to calculate the hash
/// digest for the signature. This enables the recipient to process the message in "one pass",
/// calculating the hash digest based on the Ops Packet (which occurs before the message payload),
/// and validating the cryptographic signature in the Signature Packet (which occurs after the
/// message payload) after hashing is completed.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct OnePassSignature {
    pub packet_version: Version,
    pub typ: SignatureType,
    pub hash_algorithm: HashAlgorithm,
    pub pub_algorithm: PublicKeyAlgorithm,
    pub last: u8,
    pub version_specific: OpsVersionSpecific,
}

/// Version-specific elements of a One-Pass Signature Packet:
///
/// - A v3 OPS contains the `key_id` of the signer.
/// - A v6 OPS contains the v6 `fingerprint` of the signer, and the `salt` used in the corresponding
///   signature packet.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum OpsVersionSpecific {
    V3 {
        key_id: KeyId,
    },
    V6 {
        #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
        salt: Bytes,
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
    /// Parses a `OnePassSignature` packet from the given buffer.
    pub fn from_buf<B: Buf>(packet_version: Version, mut i: B) -> Result<Self> {
        let version = i.read_u8()?;
        let typ = i.read_u8().map(SignatureType::from)?;
        let hash_algorithm = i.read_u8().map(HashAlgorithm::from)?;
        let pub_algorithm = i.read_u8().map(PublicKeyAlgorithm::from)?;

        let version_specific = match version {
            3 => {
                let key_id_raw: [u8; 8] = i.read_array::<8>()?;

                OpsVersionSpecific::V3 {
                    key_id: key_id_raw.into(),
                }
            }
            6 => {
                let salt_len = i.read_u8()?;
                let salt = i.read_take(salt_len.into())?;
                let fingerprint = i.read_array::<32>()?;

                OpsVersionSpecific::V6 { salt, fingerprint }
            }
            _ => unsupported_err!("Unsupported one pass signature packet version {version}"),
        };

        let last = i.read_u8()?;

        Ok(OnePassSignature {
            packet_version,
            typ,
            hash_algorithm,
            pub_algorithm,
            last,
            version_specific,
        })
    }

    /// Constructor for a v3 one pass signature packet.
    ///
    /// RFC 4880-era OpenPGP uses v3 one pass signature packets (NOTE: there is no v4 OPS)
    ///
    /// "When generating a one-pass signature, the OPS packet version MUST correspond to the
    /// version of the associated Signature packet, except for the historical accident that version
    /// 4 keys use a version 3 One-Pass Signature packet (there is no version 4 OPS)."
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t>
    pub fn v3(
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

    /// Constructor for a v6 one pass signature packet.
    ///
    /// Version 6 OpenPGP signatures must be combined with v6 one pass signature packets.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t>
    pub fn v6(
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
            version_specific: OpsVersionSpecific::V6 {
                salt: salt.into(),
                fingerprint,
            },
        }
    }
}

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version())?;
        writer.write_u8(self.typ.into())?;
        writer.write_u8(self.hash_algorithm.into())?;
        writer.write_u8(self.pub_algorithm.into())?;

        // salt, if v6
        if let OpsVersionSpecific::V6 { salt, .. } = &self.version_specific {
            writer.write_u8(salt.len().try_into()?)?;
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
        writer.write_u8(self.last)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1 + 1 + 1 + 1;

        // salt, if v6
        if let OpsVersionSpecific::V6 { salt, .. } = &self.version_specific {
            sum += 1;
            sum += salt.len();
        }

        match &self.version_specific {
            OpsVersionSpecific::V3 { key_id } => {
                sum += key_id.as_ref().len();
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                sum += fingerprint.len();
            }
        }
        sum += 1;
        sum
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

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn write_len(packet: OnePassSignature) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(packet: OnePassSignature) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = OnePassSignature::from_buf(packet.packet_version, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
