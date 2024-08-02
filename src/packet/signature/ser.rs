use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::Duration;
use log::debug;

use crate::errors::Result;
use crate::packet::signature::types::*;
use crate::packet::signature::SignatureConfig;
use crate::ser::Serialize;
use crate::types::Sig;
use crate::util::write_packet_length;

impl Serialize for Signature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[u8::from(self.config.version)])?;

        match self.config.version {
            SignatureVersion::V2 | SignatureVersion::V3 => self.to_writer_v3(writer),
            SignatureVersion::V4 | SignatureVersion::V6 => self.to_writer_v4_v6(writer),
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported writer")
            }
            SignatureVersion::Other(version) => bail!("Unsupported signature version {}", version),
        }
    }
}

impl Subpacket {
    /// Convert expiration time "Duration" data to OpenPGP u32 format.
    /// Use u32:MAX on overflow.
    fn duration_to_u32(d: &Duration) -> u32 {
        u32::try_from(d.num_seconds()).unwrap_or(u32::MAX)
    }

    fn body_to_writer(&self, writer: &mut impl io::Write) -> Result<()> {
        match &self.data {
            SubpacketData::SignatureCreationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            SubpacketData::SignatureExpirationTime(d) => {
                writer.write_u32::<BigEndian>(Self::duration_to_u32(d))?;
            }
            SubpacketData::KeyExpirationTime(d) => {
                writer.write_u32::<BigEndian>(Self::duration_to_u32(d))?;
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
                writer.write_all(flags)?;
            }
            SubpacketData::Features(features) => {
                writer.write_all(features)?;
            }
            SubpacketData::RevocationReason(code, reason) => {
                writer.write_all(&[u8::from(*code)])?;
                writer.write_all(reason)?;
            }
            SubpacketData::IsPrimary(is_primary) => {
                let val = u8::from(*is_primary);
                writer.write_all(&[val])?;
            }
            SubpacketData::Revocable(is_revocable) => {
                let val = u8::from(*is_revocable);
                writer.write_all(&[val])?;
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

                writer.write_u16::<BigEndian>(notation.name.len() as u16)?;

                writer.write_u16::<BigEndian>(notation.value.len() as u16)?;

                writer.write_all(&notation.name)?;
                writer.write_all(&notation.value)?;
            }
            SubpacketData::RevocationKey(rev_key) => {
                writer.write_all(&[rev_key.class as u8, rev_key.algorithm.into()])?;
                writer.write_all(&rev_key.fingerprint[..])?;
            }
            SubpacketData::SignersUserID(body) => {
                writer.write_all(body.as_ref())?;
            }
            SubpacketData::PolicyURI(uri) => {
                writer.write_all(uri.as_bytes())?;
            }
            SubpacketData::TrustSignature(depth, value) => {
                writer.write_all(&[*depth, *value])?;
            }
            SubpacketData::RegularExpression(regexp) => {
                writer.write_all(regexp)?;
            }
            SubpacketData::ExportableCertification(is_exportable) => {
                let val = u8::from(*is_exportable);
                writer.write_all(&[val])?;
            }
            SubpacketData::IssuerFingerprint(version, fp) => {
                writer.write_all(&[u8::from(*version)])?;
                writer.write_all(fp)?;
            }
            SubpacketData::PreferredEncryptionModes(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg.into()).collect::<Vec<_>>())?;
            }
            SubpacketData::IntendedRecipientFingerprint(version, fp) => {
                writer.write_all(&[u8::from(*version)])?;
                writer.write_all(fp)?;
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
                writer.write_all(&[u8::from(*pub_alg), u8::from(*hash_alg)])?;
                writer.write_all(hash)?;
            }
        }

        Ok(())
    }

    fn body_len(&self) -> Result<usize> {
        let len = match &self.data {
            SubpacketData::SignatureCreationTime(_) => 4,
            SubpacketData::SignatureExpirationTime(_) => 4,
            SubpacketData::KeyExpirationTime(_) => 4,
            SubpacketData::Issuer(_) => 8,
            SubpacketData::PreferredSymmetricAlgorithms(algs) => algs.len(),
            SubpacketData::PreferredHashAlgorithms(algs) => algs.len(),
            SubpacketData::PreferredCompressionAlgorithms(algs) => algs.len(),
            SubpacketData::KeyServerPreferences(prefs) => prefs.len(),
            SubpacketData::KeyFlags(flags) => flags.len(),
            SubpacketData::Features(features) => features.len(),

            SubpacketData::RevocationReason(_, reason) => {
                // 1 byte for revocation code + n for the reason
                1 + reason.len()
            }
            SubpacketData::IsPrimary(_) => 1,
            SubpacketData::Revocable(_) => 1,
            SubpacketData::EmbeddedSignature(sig) => {
                // TODO: find a more efficient way of doing this, if this gets expensive
                let mut buf = Vec::new();
                (*sig).to_writer(&mut buf)?;
                buf.len()
            }
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
            SubpacketData::IssuerFingerprint(_, fp) => 1 + fp.len(),
            SubpacketData::PreferredEncryptionModes(algs) => algs.len(),
            SubpacketData::IntendedRecipientFingerprint(_, fp) => 1 + fp.len(),
            SubpacketData::PreferredAeadAlgorithms(algs) => algs.len() * 2,
            SubpacketData::Experimental(_, body) => body.len(),
            SubpacketData::Other(_, body) => body.len(),
            SubpacketData::SignatureTarget(_, _, hash) => 2 + hash.len(),
        };

        Ok(len)
    }

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
            SubpacketData::IssuerFingerprint(_, _) => SubpacketType::IssuerFingerprint,
            SubpacketData::PreferredEncryptionModes(_) => SubpacketType::PreferredEncryptionModes,
            SubpacketData::IntendedRecipientFingerprint(_, _) => {
                SubpacketType::IntendedRecipientFingerprint
            }
            SubpacketData::PreferredAeadAlgorithms(_) => SubpacketType::PreferredAead,
            SubpacketData::Experimental(n, _) => SubpacketType::Experimental(*n),
            SubpacketData::Other(n, _) => SubpacketType::Other(*n),
            SubpacketData::SignatureTarget(_, _, _) => SubpacketType::SignatureTarget,
        }
    }
}

impl Serialize for Subpacket {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet_length(1 + self.body_len()?, writer)?;
        writer.write_all(&[self.typ().as_u8(self.is_critical)])?;
        self.body_to_writer(writer)?;

        Ok(())
    }
}

impl SignatureConfig {
    /// Serializes a v2 or v3 signature.
    fn to_writer_v3<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            // tag
            0x05,
            // type
            self.typ as u8,
        ])?;

        writer.write_u32::<BigEndian>(
            self.created
                .expect("must exist for a v3 signature")
                .timestamp() as u32,
        )?;

        writer.write_all(
            self.issuer
                .as_ref()
                .expect("must exist for a v3 signature")
                .as_ref(),
        )?;
        writer.write_all(&[
            // public algorithm
            u8::from(self.pub_alg),
            // hash algorithm
            u8::from(self.hash_alg),
        ])?;

        Ok(())
    }

    /// Serializes a v4 or v6 signature.
    fn to_writer_v4_v6<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            // type
            self.typ as u8,
            // public algorithm
            u8::from(self.pub_alg),
            // hash algorithm
            u8::from(self.hash_alg),
        ])?;

        // hashed subpackets
        let mut hashed_subpackets = Vec::new();
        for packet in &self.hashed_subpackets {
            packet.to_writer(&mut hashed_subpackets)?;
        }

        match self.version {
            SignatureVersion::V4 => writer.write_u16::<BigEndian>(hashed_subpackets.len() as u16)?,
            SignatureVersion::V6 => writer.write_u32::<BigEndian>(hashed_subpackets.len() as u32)?,
            v => unimplemented_err!("signature version {:?}", v),
        }

        writer.write_all(&hashed_subpackets)?;

        // unhashed subpackets
        let mut unhashed_subpackets = Vec::new();
        for packet in &self.unhashed_subpackets {
            packet.to_writer(&mut unhashed_subpackets)?;
        }

        match self.version {
            SignatureVersion::V4 => {
                writer.write_u16::<BigEndian>(unhashed_subpackets.len() as u16)?
            }
            SignatureVersion::V6 => {
                writer.write_u32::<BigEndian>(unhashed_subpackets.len() as u32)?
            }
            v => unimplemented_err!("signature version {:?}", v),
        }

        writer.write_all(&unhashed_subpackets)?;

        Ok(())
    }
}

impl Signature {
    /// Serializes a v2 or v3 signature.
    fn to_writer_v3<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer_v3(writer)?;

        // signed hash value
        writer.write_all(&self.signed_hash_value)?;

        // the actual signature
        match &self.signature {
            Sig::Mpis(mpis) => {
                // the actual signature
                for val in mpis {
                    debug!("writing: {}", hex::encode(val));
                    val.to_writer(writer)?;
                }
            }
            Sig::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }

    /// Serializes a v4 or v6 signature.
    fn to_writer_v4_v6<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer_v4_v6(writer)?;

        // signed hash value
        writer.write_all(&self.signed_hash_value)?;

        // salt, if v6
        if self.config.version == SignatureVersion::V6 {
            let salt: &[u8] = self.config.salt.as_ref().expect("v6");

            let len: u8 = salt.len().try_into()?;
            writer.write_all(&[len])?;
            writer.write_all(salt)?;
        }

        // the actual signature
        match &self.signature {
            Sig::Mpis(mpis) => {
                // the actual signature
                for val in mpis {
                    debug!("writing: {}", hex::encode(val));
                    val.to_writer(writer)?;
                }
            }
            Sig::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use super::*;
    use crate::packet::{Packet, PacketParser};

    fn test_roundtrip(name: &str) {
        let f = File::open(Path::new("./tests/openpgp/samplemsgs").join(name)).unwrap();

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
