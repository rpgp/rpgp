use std::io;

use byteorder::{BigEndian, WriteBytesExt};

use crate::errors::Result;
use crate::packet::signature::types::*;
use crate::packet::signature::SignatureConfig;
use crate::ser::Serialize;
use crate::util::write_packet_length;

impl Serialize for Signature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.config.version as u8])?;

        match self.config.version {
            SignatureVersion::V2 | SignatureVersion::V3 => self.to_writer_v3(writer),
            SignatureVersion::V4 | SignatureVersion::V5 => self.to_writer_v4(writer),
        }
    }
}

impl Subpacket {
    fn body_to_writer(&self, writer: &mut impl io::Write) -> Result<()> {
        match &self.data {
            SubpacketData::SignatureCreationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            SubpacketData::SignatureExpirationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            SubpacketData::KeyExpirationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            SubpacketData::Issuer(id) => {
                writer.write_all(id.as_ref())?;
            }
            SubpacketData::PreferredSymmetricAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            SubpacketData::PreferredHashAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            SubpacketData::PreferredCompressionAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
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
                writer.write_all(&[rev_key.class as u8, rev_key.algorithm as u8])?;
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
                writer.write_all(&[*version as u8])?;
                writer.write_all(fp)?;
            }
            SubpacketData::PreferredAeadAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            SubpacketData::Experimental(_, body) => {
                writer.write_all(body)?;
            }
            SubpacketData::Other(_, body) => {
                writer.write_all(body)?;
            }
            SubpacketData::SignatureTarget(pub_alg, hash_alg, hash) => {
                writer.write_all(&[*pub_alg as u8, *hash_alg as u8])?;
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
            SubpacketData::PreferredAeadAlgorithms(algs) => algs.len(),
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
            self.pub_alg as u8,
            // hash algorithm
            self.hash_alg as u8,
        ])?;

        Ok(())
    }

    /// Serializes a v4 or v5 signature.
    fn to_writer_v4<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            // type
            self.typ as u8,
            // public algorithm
            self.pub_alg as u8,
            // hash algorithm
            self.hash_alg as u8,
        ])?;

        // hashed subpackets
        let mut hashed_subpackets = Vec::new();
        for packet in &self.hashed_subpackets {
            packet.to_writer(&mut hashed_subpackets)?;
        }

        writer.write_u16::<BigEndian>(hashed_subpackets.len() as u16)?;
        writer.write_all(&hashed_subpackets)?;

        // unhashed subpackets
        let mut unhashed_subpackets = Vec::new();
        for packet in &self.unhashed_subpackets {
            packet.to_writer(&mut unhashed_subpackets)?;
        }

        writer.write_u16::<BigEndian>(unhashed_subpackets.len() as u16)?;
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
        for val in &self.signature {
            debug!("writing: {}", hex::encode(val));
            val.to_writer(writer)?;
        }

        Ok(())
    }

    /// Serializes a v4 or v5 signature.
    fn to_writer_v4<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer_v4(writer)?;

        // signed hash value
        writer.write_all(&self.signed_hash_value)?;

        // the actual signature
        for val in &self.signature {
            debug!("writing signature: {}", hex::encode(val));
            val.to_writer(writer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use crate::packet::{Packet, PacketParser};
    use crate::ser::Serialize;

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
