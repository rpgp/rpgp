use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::Duration;
use log::debug;

use crate::{
    errors::{bail, unimplemented_err, unsupported_err, Result},
    packet::{
        signature::{types::*, SignatureConfig},
        SignatureVersionSpecific, Subpacket, SubpacketData, SubpacketType,
    },
    ser::Serialize,
};

impl Serialize for Signature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version().into())?;

        match &self.inner {
            InnerSignature::Known {
                config,
                signed_hash_value,
                signature,
                ..
            } => match config.version() {
                SignatureVersion::V2 | SignatureVersion::V3 => {
                    config.to_writer_v3(writer)?;
                    // signed hash value
                    writer.write_all(signed_hash_value)?;
                    // the actual cryptographic signature
                    signature.to_writer(writer)?;
                }
                SignatureVersion::V4 | SignatureVersion::V6 => {
                    config.to_writer_v4_v6(writer)?;

                    // signed hash value
                    writer.write_all(signed_hash_value)?;

                    // salt, if v6
                    if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
                        debug!("writing salt {} bytes", salt.len());
                        writer.write_u8(salt.len().try_into()?)?;
                        writer.write_all(salt)?;
                    }

                    // the actual cryptographic signature
                    signature.to_writer(writer)?;
                }
                SignatureVersion::V5 => {
                    unsupported_err!("crate V5 signature")
                }
                _ => unreachable!(),
            },
            InnerSignature::Unknown { data, .. } => {
                writer.write_all(data)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1;
        match &self.inner {
            InnerSignature::Known {
                config,
                signed_hash_value,
                signature,
            } => match config.version() {
                SignatureVersion::V2 | SignatureVersion::V3 => {
                    sum += config.write_len_v3();
                    sum += signed_hash_value.len();
                    sum += signature.write_len();
                }
                SignatureVersion::V4 | SignatureVersion::V6 => {
                    sum += config.write_len_v4_v6();
                    sum += signed_hash_value.len();

                    if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
                        sum += 1;
                        sum += salt.len();
                    }

                    sum += signature.write_len();
                }
                SignatureVersion::V5 => panic!("v5 signature unsupported writer"),
                _ => unreachable!(),
            },
            InnerSignature::Unknown { data, .. } => {
                sum += data.len();
            }
        }
        sum
    }
}

/// Convert expiration time "Duration" data to OpenPGP u32 format.
/// Use u32:MAX on overflow.
fn duration_to_u32(d: &Duration) -> u32 {
    u32::try_from(d.num_seconds()).unwrap_or(u32::MAX)
}

impl Subpacket {
    pub fn typ(&self) -> SubpacketType {
        match &self.data {
            SubpacketData::SignatureCreationTime(_) => SubpacketType::SignatureCreationTime,
            SubpacketData::SignatureExpirationTime(_) => SubpacketType::SignatureExpirationTime,
            SubpacketData::KeyExpirationTime(_) => SubpacketType::KeyExpirationTime,
            SubpacketData::Issuer(_) => SubpacketType::Issuer,
            SubpacketData::PreferredSymmetricAlgorithms(_) => {
                SubpacketType::PreferredSymmetricAlgorithms
            }
            SubpacketData::PreferredHashAlgorithms(_) => SubpacketType::PreferredHashAlgorithms,
            SubpacketData::PreferredCompressionAlgorithms(_) => {
                SubpacketType::PreferredCompressionAlgorithms
            }
            SubpacketData::KeyServerPreferences(_) => SubpacketType::KeyServerPreferences,
            SubpacketData::KeyFlags(_) => SubpacketType::KeyFlags,
            SubpacketData::Features(_) => SubpacketType::Features,
            SubpacketData::RevocationReason(_, _) => SubpacketType::RevocationReason,
            SubpacketData::IsPrimary(_) => SubpacketType::PrimaryUserId,
            SubpacketData::Revocable(_) => SubpacketType::Revocable,
            SubpacketData::EmbeddedSignature(_) => SubpacketType::EmbeddedSignature,
            SubpacketData::PreferredKeyServer(_) => SubpacketType::PreferredKeyServer,
            SubpacketData::Notation(_) => SubpacketType::Notation,
            SubpacketData::RevocationKey(_) => SubpacketType::RevocationKey,
            SubpacketData::SignersUserID(_) => SubpacketType::SignersUserID,
            SubpacketData::PolicyURI(_) => SubpacketType::PolicyURI,
            SubpacketData::TrustSignature(_, _) => SubpacketType::TrustSignature,
            SubpacketData::RegularExpression(_) => SubpacketType::RegularExpression,
            SubpacketData::ExportableCertification(_) => SubpacketType::ExportableCertification,
            SubpacketData::IssuerFingerprint(_) => SubpacketType::IssuerFingerprint,
            SubpacketData::PreferredEncryptionModes(_) => SubpacketType::PreferredEncryptionModes,
            SubpacketData::IntendedRecipientFingerprint(_) => {
                SubpacketType::IntendedRecipientFingerprint
            }
            SubpacketData::PreferredAeadAlgorithms(_) => SubpacketType::PreferredAead,
            SubpacketData::Experimental(n, _) => SubpacketType::Experimental(*n),
            SubpacketData::Other(n, _) => SubpacketType::Other(*n),
            SubpacketData::SignatureTarget(_, _, _) => SubpacketType::SignatureTarget,
        }
    }
}

impl Serialize for SubpacketData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        debug!("writing subpacket: {:?}", self);
        match &self {
            SubpacketData::SignatureCreationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp().try_into()?)?;
            }
            SubpacketData::SignatureExpirationTime(d) => {
                writer.write_u32::<BigEndian>(duration_to_u32(d))?;
            }
            SubpacketData::KeyExpirationTime(d) => {
                writer.write_u32::<BigEndian>(duration_to_u32(d))?;
            }
            SubpacketData::Issuer(id) => {
                writer.write_all(id.as_ref())?;
            }
            SubpacketData::PreferredSymmetricAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| u8::from(alg)).collect::<Vec<_>>())?;
            }
            SubpacketData::PreferredHashAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg.into()).collect::<Vec<_>>())?;
            }
            SubpacketData::PreferredCompressionAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| u8::from(alg)).collect::<Vec<_>>())?;
            }
            SubpacketData::KeyServerPreferences(prefs) => {
                writer.write_all(prefs)?;
            }
            SubpacketData::KeyFlags(flags) => {
                flags.to_writer(writer)?;
            }
            SubpacketData::Features(features) => {
                features.to_writer(writer)?;
            }
            SubpacketData::RevocationReason(code, reason) => {
                writer.write_u8((*code).into())?;
                writer.write_all(reason)?;
            }
            SubpacketData::IsPrimary(is_primary) => {
                writer.write_u8((*is_primary).into())?;
            }
            SubpacketData::Revocable(is_revocable) => {
                writer.write_u8((*is_revocable).into())?;
            }
            SubpacketData::EmbeddedSignature(inner_sig) => {
                (*inner_sig).to_writer(writer)?;
            }
            SubpacketData::PreferredKeyServer(server) => {
                writer.write_all(server.as_bytes())?;
            }
            SubpacketData::Notation(notation) => {
                let is_readable = if notation.readable { 0x80 } else { 0 };
                writer.write_all(&[is_readable, 0, 0, 0])?;

                writer.write_u16::<BigEndian>(notation.name.len().try_into()?)?;

                writer.write_u16::<BigEndian>(notation.value.len().try_into()?)?;

                writer.write_all(&notation.name)?;
                writer.write_all(&notation.value)?;
            }
            SubpacketData::RevocationKey(rev_key) => {
                writer.write_u8(rev_key.class as u8)?;
                writer.write_u8(rev_key.algorithm.into())?;
                writer.write_all(&rev_key.fingerprint[..])?;
            }
            SubpacketData::SignersUserID(body) => {
                writer.write_all(body.as_ref())?;
            }
            SubpacketData::PolicyURI(uri) => {
                writer.write_all(uri.as_bytes())?;
            }
            SubpacketData::TrustSignature(depth, value) => {
                writer.write_u8(*depth)?;
                writer.write_u8(*value)?;
            }
            SubpacketData::RegularExpression(regexp) => {
                writer.write_all(regexp)?;
            }
            SubpacketData::ExportableCertification(is_exportable) => {
                writer.write_u8((*is_exportable).into())?;
            }
            SubpacketData::IssuerFingerprint(fp) => {
                if let Some(version) = fp.version() {
                    writer.write_u8(version.into())?;
                    writer.write_all(fp.as_bytes())?;
                } else {
                    bail!("IssuerFingerprint: needs versioned fingerprint")
                }
            }
            SubpacketData::PreferredEncryptionModes(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg.into()).collect::<Vec<_>>())?;
            }
            SubpacketData::IntendedRecipientFingerprint(fp) => {
                if let Some(version) = fp.version() {
                    writer.write_u8(version.into())?;
                    writer.write_all(fp.as_bytes())?;
                } else {
                    bail!("IntendedRecipientFingerprint: needs versioned fingerprint")
                }
            }
            SubpacketData::PreferredAeadAlgorithms(algs) => {
                writer.write_all(
                    &algs
                        .iter()
                        .flat_map(|&(sym_alg, aead)| [sym_alg.into(), aead.into()])
                        .collect::<Vec<_>>(),
                )?;
            }
            SubpacketData::Experimental(_, body) => {
                writer.write_all(body)?;
            }
            SubpacketData::Other(_, body) => {
                writer.write_all(body)?;
            }
            SubpacketData::SignatureTarget(pub_alg, hash_alg, hash) => {
                writer.write_u8((*pub_alg).into())?;
                writer.write_u8((*hash_alg).into())?;
                writer.write_all(hash)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let len = match &self {
            SubpacketData::SignatureCreationTime(_) => 4,
            SubpacketData::SignatureExpirationTime(_) => 4,
            SubpacketData::KeyExpirationTime(_) => 4,
            SubpacketData::Issuer(_) => 8,
            SubpacketData::PreferredSymmetricAlgorithms(algs) => algs.len(),
            SubpacketData::PreferredHashAlgorithms(algs) => algs.len(),
            SubpacketData::PreferredCompressionAlgorithms(algs) => algs.len(),
            SubpacketData::KeyServerPreferences(prefs) => prefs.len(),
            SubpacketData::KeyFlags(flags) => flags.write_len(),
            SubpacketData::Features(features) => features.write_len(),

            SubpacketData::RevocationReason(_, reason) => {
                // 1 byte for revocation code + n for the reason
                1 + reason.len()
            }
            SubpacketData::IsPrimary(_) => 1,
            SubpacketData::Revocable(_) => 1,
            SubpacketData::EmbeddedSignature(sig) => (*sig).write_len(),
            SubpacketData::PreferredKeyServer(server) => server.chars().count(),
            SubpacketData::Notation(n) => {
                // 4 for the flags, 2 for the name length, 2 for the value length, m for the name, n for the value
                4 + 2 + 2 + n.name.len() + n.value.len()
            }
            SubpacketData::RevocationKey(_) => 22,
            SubpacketData::SignersUserID(body) => {
                let bytes: &[u8] = body.as_ref();
                bytes.len()
            }
            SubpacketData::PolicyURI(uri) => uri.len(),
            SubpacketData::TrustSignature(_, _) => 2,
            SubpacketData::RegularExpression(regexp) => regexp.len(),
            SubpacketData::ExportableCertification(_) => 1,
            SubpacketData::IssuerFingerprint(fp) => 1 + fp.len(),
            SubpacketData::PreferredEncryptionModes(algs) => algs.len(),
            SubpacketData::IntendedRecipientFingerprint(fp) => 1 + fp.len(),
            SubpacketData::PreferredAeadAlgorithms(algs) => algs.len() * 2,
            SubpacketData::Experimental(_, body) => body.len(),
            SubpacketData::Other(_, body) => body.len(),
            SubpacketData::SignatureTarget(_, _, hash) => 2 + hash.len(),
        };

        len
    }
}

impl Serialize for Subpacket {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.len.to_writer(writer)?;
        writer.write_u8(self.typ().as_u8(self.is_critical))?;
        self.data.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.len.len();
        sum += self.len.write_len();
        sum
    }
}

impl SignatureConfig {
    /// Serializes a v2 or v3 signature.
    fn to_writer_v3<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(0x05)?; // 1-octet length of the following hashed material; it MUST be 5
        writer.write_u8(self.typ.into())?; // type

        if let SignatureVersionSpecific::V2 { created, issuer }
        | SignatureVersionSpecific::V3 { created, issuer } = &self.version_specific
        {
            writer.write_u32::<BigEndian>(created.timestamp().try_into()?)?;
            writer.write_all(issuer.as_ref())?;
        } else {
            bail!("expecting SignatureVersionSpecific::V3 for a v2/v3 signature")
        }

        writer.write_u8(self.pub_alg.into())?; // public algorithm
        writer.write_u8(self.hash_alg.into())?; // hash algorithm

        Ok(())
    }

    pub(super) fn write_len_v3(&self) -> usize {
        let mut sum = 1 + 1;

        if let SignatureVersionSpecific::V2 { issuer, .. }
        | SignatureVersionSpecific::V3 { issuer, .. } = &self.version_specific
        {
            sum += 4;
            sum += issuer.as_ref().len();
        } else {
            panic!("expecting SignatureVersionSpecific::V3 for a v2/v3 signature")
        }

        sum += 1 + 1;

        sum
    }

    /// Serializes a v4 or v6 signature.
    fn to_writer_v4_v6<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.typ.into())?; // type

        writer.write_u8(self.pub_alg.into())?; // public algorithm
        writer.write_u8(self.hash_alg.into())?; // hash algorithm

        // hashed subpackets
        let hashed_sub_len = self.hashed_subpackets.write_len();
        match self.version() {
            SignatureVersion::V4 => writer.write_u16::<BigEndian>(hashed_sub_len.try_into()?)?,
            SignatureVersion::V6 => writer.write_u32::<BigEndian>(hashed_sub_len.try_into()?)?,
            v => unimplemented_err!("signature version {:?}", v),
        }

        for packet in &self.hashed_subpackets {
            packet.to_writer(writer)?;
        }

        // unhashed subpackets
        let unhashed_sub_len = self.unhashed_subpackets.write_len();

        match self.version() {
            SignatureVersion::V4 => writer.write_u16::<BigEndian>(unhashed_sub_len.try_into()?)?,
            SignatureVersion::V6 => writer.write_u32::<BigEndian>(unhashed_sub_len.try_into()?)?,
            v => unimplemented_err!("signature version {:?}", v),
        }

        for packet in &self.unhashed_subpackets {
            packet.to_writer(writer)?;
        }

        Ok(())
    }

    pub(super) fn write_len_v4_v6(&self) -> usize {
        let mut sum = 1 + 1 + 1;

        // hashed subpackets
        sum += self.hashed_subpackets.write_len();

        match self.version() {
            SignatureVersion::V4 => {
                sum += 2;
            }
            SignatureVersion::V6 => {
                sum += 4;
            }
            v => panic!("signature version {:?}", v),
        }

        // unhashed subpackets
        sum += self.unhashed_subpackets.write_len();
        match self.version() {
            SignatureVersion::V4 => {
                sum += 2;
            }
            SignatureVersion::V6 => {
                sum += 4;
            }
            v => panic!("signature version {:?}", v),
        }

        sum
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        fs::File,
        io::{BufReader, Read},
        path::Path,
    };

    use super::*;
    use crate::packet::{Packet, PacketParser};

    fn test_roundtrip(name: &str) {
        let f = BufReader::new(
            std::fs::File::open(Path::new("./tests/openpgp/samplemsgs").join(name)).unwrap(),
        );

        let packets: Vec<Packet> = PacketParser::new(f).collect::<Result<_>>().unwrap();
        let mut serialized = Vec::new();

        for p in &packets {
            if let Packet::Signature(_) = p {
                p.to_writer(&mut serialized).unwrap();
            } else {
                panic!("unexpected packet: {p:?}");
            };
        }

        let bytes = {
            let mut f = File::open(Path::new("./tests/openpgp/samplemsgs").join(name)).unwrap();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();
            bytes
        };

        assert_eq!(bytes, serialized, "failed to roundtrip");
    }

    #[test]
    fn packet_signature_roundtrip_openpgp_sig_1_key_1() {
        test_roundtrip("sig-1-key-1.sig");
    }

    #[test]
    fn packet_signature_roundtrip_openpgp_sig_1_key_2() {
        test_roundtrip("sig-1-key-2.sig");
    }

    #[test]
    fn packet_signature_roundtrip_openpgp_sig_2_keys_1() {
        test_roundtrip("sig-2-keys-1.sig");
    }

    #[test]
    fn packet_signature_roundtrip_openpgp_sig_2_keys_2() {
        test_roundtrip("sig-2-keys-2.sig");
    }

    // Tries to roundtrip a signature containing a name + E-Mail with complicated multibyte unicode characters
    #[test]
    fn packet_signature_roundtrip_openpgp_with_unicode() {
        test_roundtrip("unicode.sig");
    }
}
