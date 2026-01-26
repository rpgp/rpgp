use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use log::debug;
#[cfg(test)]
use proptest::prelude::*;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, Result},
    packet::{
        signature::SignatureType, InnerSignature, PacketHeader, PacketTrait, Signature,
        SignatureVersionSpecific,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{KeyId, Tag},
};

/// One-Pass Signature Packet
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t>
///
/// A One-Pass Signature (Ops) Packet acts as a companion to a [`Signature`] Packet.
/// In modern OpenPGP messages, Ops and Signature packets occur in pairs, bracketing the message payload.
///
/// The Ops packet contains all the information that a recipient needs to calculate the hash
/// digest for the signature. This enables the recipient to process the message in "one pass",
/// calculating the hash digest based on the Ops Packet (which occurs before the message payload),
/// and validating the cryptographic signature in the Signature Packet (which occurs after the
/// message payload) after hashing is completed.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct OnePassSignature {
    packet_header: PacketHeader,
    typ: SignatureType,
    hash_algorithm: HashAlgorithm,
    pub_algorithm: PublicKeyAlgorithm,
    last: u8,
    version_specific: OpsVersionSpecific,
}

/// Version-specific data of a [`OnePassSignature`] packet
///
/// - A v3 OPS contains the `key_id` of the signer.
/// - A v6 OPS contains the v6 `fingerprint` of the signer, and the `salt` used in the signature.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum OpsVersionSpecific {
    V3 {
        key_id: KeyId,
    },
    V6 {
        #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
        #[debug("{}", hex::encode(salt))]
        salt: Bytes,
        #[debug("{}", hex::encode(fingerprint))]
        fingerprint: [u8; 32],
    },
    #[cfg_attr(test, proptest(skip))]
    Unknown {
        #[debug("{:X}", version)]
        version: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl Serialize for OpsVersionSpecific {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        // salt, if v6
        if let OpsVersionSpecific::V6 { salt, .. } = self {
            writer.write_u8(salt.len().try_into()?)?;
            writer.write_all(salt)?;
        }

        match self {
            OpsVersionSpecific::V3 { key_id } => {
                writer.write_all(key_id.as_ref())?;
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                writer.write_all(fingerprint.as_ref())?;
            }
            OpsVersionSpecific::Unknown { data, .. } => {
                writer.write_all(data)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        // salt, if v6
        if let OpsVersionSpecific::V6 { salt, .. } = self {
            sum += 1;
            sum += salt.len();
        }
        match self {
            OpsVersionSpecific::V3 { key_id } => {
                sum += key_id.as_ref().len();
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                sum += fingerprint.len();
            }
            OpsVersionSpecific::Unknown { data, .. } => {
                sum += data.len();
            }
        }
        sum
    }
}

impl OnePassSignature {
    pub fn version(&self) -> u8 {
        match self.version_specific {
            OpsVersionSpecific::V3 { .. } => 3,
            OpsVersionSpecific::V6 { .. } => 6,
            OpsVersionSpecific::Unknown { version, .. } => version,
        }
    }

    /// Check if this OPS contains the same metadata as `sig`.
    ///
    /// This is used to determine if the Signature packet in a one pass signed message is acceptable
    /// after having validated based on the preceding One Pass Signature packet.
    ///
    /// If this returns `false`, the signature in a one pass signed message is always considered
    /// invalid.
    pub fn matches(&self, sig: &Signature) -> bool {
        let InnerSignature::Known {
            config: sig_config, ..
        } = &sig.inner
        else {
            // We don't know how to verify signatures for InnerSignature::Unknown, best to give up
            return false;
        };

        if self.typ != sig_config.typ {
            debug!(
                "Unmatched signature type: Ops {:?}, Sig {:?}",
                self.typ, sig_config.typ
            );
            return false;
        }

        if self.hash_algorithm != sig_config.hash_alg {
            debug!(
                "Unmatched hash algorithms: Ops {:?}, Sig {:?}",
                self.hash_algorithm, sig_config.hash_alg
            );
            return false;
        }

        if self.pub_algorithm != sig_config.pub_alg {
            debug!(
                "Unmatched public key algorithms: Ops {:?}, Sig {:?}",
                self.pub_algorithm, sig_config.pub_alg
            );
            return false;
        }

        match (&self.version_specific, &sig_config.version_specific) {
            (OpsVersionSpecific::V3 { .. }, SignatureVersionSpecific::V4) => {}
            (
                OpsVersionSpecific::V6 { salt: ops_salt, .. },
                SignatureVersionSpecific::V6 { salt: sig_salt, .. },
            ) => {
                if ops_salt != sig_salt {
                    debug!(
                        "Salt mismatch between Ops and Signature: {ops_salt:02x?} / {sig_salt:02x?}"
                    );
                    return false;
                }
            }
            _ => {
                debug!("Illegal combination of Ops and Signature version: {self:?}, {sig:?}");
                return false;
            }
        }

        true
    }
}

impl OnePassSignature {
    /// Parses a `OnePassSignature` packet.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        let version = i.read_u8()?;
        let typ = i.read_u8().map(SignatureType::from)?;
        let hash_algorithm = i.read_u8().map(HashAlgorithm::from)?;
        let pub_algorithm = i.read_u8().map(PublicKeyAlgorithm::from)?;

        let (version_specific, last) = match version {
            3 => {
                let key_id_raw: [u8; 8] = i.read_arr::<8>()?;

                let last = i.read_u8()?;
                (
                    OpsVersionSpecific::V3 {
                        key_id: key_id_raw.into(),
                    },
                    last,
                )
            }
            6 => {
                let salt_len = i.read_u8()?;
                let salt = i.take_bytes(salt_len.into())?.freeze();
                let fingerprint = i.read_arr::<32>()?;
                let last = i.read_u8()?;

                (OpsVersionSpecific::V6 { salt, fingerprint }, last)
            }
            _ => {
                let mut data = i.rest()?.freeze();
                let last = if !data.is_empty() {
                    let last = data.split_off(data.len() - 1);
                    last[0]
                } else {
                    bail!("missing last field");
                };
                (OpsVersionSpecific::Unknown { version, data }, last)
            }
        };

        Ok(OnePassSignature {
            packet_header,
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
        let version_specific = OpsVersionSpecific::V3 { key_id };
        let len = WRITE_LEN_OVERHEAD + version_specific.write_len();
        let packet_header =
            PacketHeader::new_fixed(Tag::OnePassSignature, len.try_into().expect("fixed"));

        OnePassSignature {
            packet_header,
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific,
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
        let version_specific = OpsVersionSpecific::V6 {
            salt: salt.into(),
            fingerprint,
        };
        let len = WRITE_LEN_OVERHEAD + version_specific.write_len();
        let packet_header =
            PacketHeader::new_fixed(Tag::OnePassSignature, len.try_into().expect("fixed"));

        OnePassSignature {
            packet_header,
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific,
        }
    }

    /// Returns true if this expects another one pass signature afterwards.
    pub fn is_nested(&self) -> bool {
        self.last == 0
    }

    /// Marks this as being part of a nested signature structure.
    pub fn set_is_nested(&mut self) {
        self.last = 0;
    }

    /// Returns the used hash algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Returns the used public key algorithm.
    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithm {
        self.pub_algorithm
    }

    /// Returns the signature type.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    pub fn version_specific(&self) -> &OpsVersionSpecific {
        &self.version_specific
    }
}

const WRITE_LEN_OVERHEAD: usize = 5;

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version())?;
        writer.write_u8(self.typ.into())?;
        writer.write_u8(self.hash_algorithm.into())?;
        writer.write_u8(self.pub_algorithm.into())?;

        self.version_specific.to_writer(writer)?;
        writer.write_u8(self.last)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = WRITE_LEN_OVERHEAD;
        sum += self.version_specific.write_len();
        sum
    }
}

impl PacketTrait for OnePassSignature {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
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
            let new_packet = OnePassSignature::try_from_reader(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
