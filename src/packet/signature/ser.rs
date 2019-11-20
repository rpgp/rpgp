use std::io;

use byteorder::{BigEndian, WriteBytesExt};

use crate::errors::Result;
use crate::packet::signature::types::*;
use crate::packet::signature::SignatureConfig;
use crate::ser::Serialize;
use crate::util::{write_packet_length, write_string};

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
        match self {
            Subpacket::SignatureCreationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            Subpacket::SignatureExpirationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            Subpacket::KeyExpirationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            Subpacket::Issuer(id) => {
                writer.write_all(id.as_ref())?;
            }
            Subpacket::PreferredSymmetricAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            Subpacket::PreferredHashAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            Subpacket::PreferredCompressionAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            Subpacket::KeyServerPreferences(prefs) => {
                writer.write_all(prefs)?;
            }
            Subpacket::KeyFlags(flags) => {
                writer.write_all(flags)?;
            }
            Subpacket::Features(features) => {
                writer.write_all(features)?;
            }
            Subpacket::RevocationReason(code, reason) => {
                writer.write_all(&[*code as u8])?;
                writer.write_all(&write_string(reason))?;
            }
            Subpacket::IsPrimary(is_primary) => {
                let val = if *is_primary { 1u8 } else { 0u8 };
                writer.write_all(&[val])?;
            }
            Subpacket::Revocable(is_revocable) => {
                let val = if *is_revocable { 1u8 } else { 0u8 };
                writer.write_all(&[val])?;
            }
            Subpacket::EmbeddedSignature(inner_sig) => {
                (*inner_sig).to_writer(writer)?;
            }
            Subpacket::PreferredKeyServer(server) => {
                writer.write_all(&write_string(server))?;
            }
            Subpacket::Notation(notation) => {
                let is_readable = if notation.readable { 0x80 } else { 0 };
                writer.write_all(&[is_readable, 0, 0, 0])?;

                let name_bytes = write_string(&notation.name);
                writer.write_u16::<BigEndian>(name_bytes.len() as u16)?;

                let value_bytes = write_string(&notation.value);
                writer.write_u16::<BigEndian>(value_bytes.len() as u16)?;

                writer.write_all(&name_bytes)?;
                writer.write_all(&value_bytes)?;
            }
            Subpacket::RevocationKey(rev_key) => {
                writer.write_all(&[rev_key.class as u8, rev_key.algorithm as u8])?;
                writer.write_all(&rev_key.fingerprint[..])?;
            }
            Subpacket::SignersUserID(body) => {
                writer.write_all(body.as_ref())?;
            }
            Subpacket::PolicyURI(uri) => {
                writer.write_all(&write_string(uri))?;
            }
            Subpacket::TrustSignature(depth, value) => {
                writer.write_all(&[*depth, *value])?;
            }
            Subpacket::RegularExpression(regexp) => {
                writer.write_all(&write_string(regexp))?;
            }
            Subpacket::ExportableCertification(is_exportable) => {
                let val = if *is_exportable { 1 } else { 0 };
                writer.write_all(&[val])?;
            }
            Subpacket::IssuerFingerprint(version, fp) => {
                writer.write_all(&[*version as u8])?;
                writer.write_all(fp)?;
            }
            Subpacket::PreferredAeadAlgorithms(algs) => {
                writer.write_all(&algs.iter().map(|&alg| alg as u8).collect::<Vec<_>>())?;
            }
            Subpacket::Experimental(_, body) => {
                writer.write_all(body)?;
            }
            Subpacket::Other(_, body) => {
                writer.write_all(body)?;
            }
            Subpacket::SignatureTarget(pub_alg, hash_alg, hash) => {
                writer.write_all(&[*pub_alg as u8, *hash_alg as u8])?;
                writer.write_all(hash)?;
            }
        }

        Ok(())
    }

    fn body_len(&self) -> Result<usize> {
        let len = match self {
            Subpacket::SignatureCreationTime(_) => 4,
            Subpacket::SignatureExpirationTime(_) => 4,
            Subpacket::KeyExpirationTime(_) => 4,
            Subpacket::Issuer(_) => 8,
            Subpacket::PreferredSymmetricAlgorithms(algs) => algs.len(),
            Subpacket::PreferredHashAlgorithms(algs) => algs.len(),
            Subpacket::PreferredCompressionAlgorithms(algs) => algs.len(),
            Subpacket::KeyServerPreferences(prefs) => prefs.len(),
            Subpacket::KeyFlags(flags) => flags.len(),
            Subpacket::Features(features) => features.len(),
            Subpacket::RevocationReason(_, reason) => 1 + reason.chars().count(),
            Subpacket::IsPrimary(_) => 1,
            Subpacket::Revocable(_) => 1,
            Subpacket::EmbeddedSignature(sig) => {
                // TODO: find a more efficient way of doing this, if this gets expensive
                let mut buf = Vec::new();
                (*sig).to_writer(&mut buf)?;
                buf.len()
            }
            Subpacket::PreferredKeyServer(server) => server.chars().count(),
            Subpacket::Notation(n) => 4 + 2 + 2 + n.name.chars().count() + n.value.chars().count(),
            Subpacket::RevocationKey(_) => 22,
            Subpacket::SignersUserID(body) => {
                let bytes: &[u8] = body.as_ref();
                bytes.len()
            }
            Subpacket::PolicyURI(uri) => uri.as_bytes().len(),
            Subpacket::TrustSignature(_, _) => 2,
            Subpacket::RegularExpression(regexp) => regexp.as_bytes().len(),
            Subpacket::ExportableCertification(_) => 1,
            Subpacket::IssuerFingerprint(_, fp) => 1 + fp.len(),
            Subpacket::PreferredAeadAlgorithms(algs) => algs.len(),
            Subpacket::Experimental(_, body) => body.len(),
            Subpacket::Other(_, body) => body.len(),
            Subpacket::SignatureTarget(_, _, hash) => 2 + hash.len(),
        };

        Ok(len)
    }

    pub fn typ(&self) -> SubpacketType {
        match self {
            Subpacket::SignatureCreationTime(_) => SubpacketType::SignatureCreationTime,
            Subpacket::SignatureExpirationTime(_) => SubpacketType::SignatureExpirationTime,
            Subpacket::KeyExpirationTime(_) => SubpacketType::KeyExpirationTime,
            Subpacket::Issuer(_) => SubpacketType::Issuer,
            Subpacket::PreferredSymmetricAlgorithms(_) => {
                SubpacketType::PreferredSymmetricAlgorithms
            }
            Subpacket::PreferredHashAlgorithms(_) => SubpacketType::PreferredHashAlgorithms,
            Subpacket::PreferredCompressionAlgorithms(_) => {
                SubpacketType::PreferredCompressionAlgorithms
            }
            Subpacket::KeyServerPreferences(_) => SubpacketType::KeyServerPreferences,
            Subpacket::KeyFlags(_) => SubpacketType::KeyFlags,
            Subpacket::Features(_) => SubpacketType::Features,
            Subpacket::RevocationReason(_, _) => SubpacketType::RevocationReason,
            Subpacket::IsPrimary(_) => SubpacketType::PrimaryUserId,
            Subpacket::Revocable(_) => SubpacketType::Revocable,
            Subpacket::EmbeddedSignature(_) => SubpacketType::EmbeddedSignature,
            Subpacket::PreferredKeyServer(_) => SubpacketType::PreferredKeyServer,
            Subpacket::Notation(_) => SubpacketType::Notation,
            Subpacket::RevocationKey(_) => SubpacketType::RevocationKey,
            Subpacket::SignersUserID(_) => SubpacketType::SignersUserID,
            Subpacket::PolicyURI(_) => SubpacketType::PolicyURI,
            Subpacket::TrustSignature(_, _) => SubpacketType::TrustSignature,
            Subpacket::RegularExpression(_) => SubpacketType::RegularExpression,
            Subpacket::ExportableCertification(_) => SubpacketType::ExportableCertification,
            Subpacket::IssuerFingerprint(_, _) => SubpacketType::IssuerFingerprint,
            Subpacket::PreferredAeadAlgorithms(_) => SubpacketType::PreferredAead,
            Subpacket::Experimental(n, _) => SubpacketType::Experimental(*n),
            Subpacket::Other(n, _) => SubpacketType::Other(*n),
            Subpacket::SignatureTarget(_, _, _) => SubpacketType::SignatureTarget,
        }
    }
}

impl Serialize for Subpacket {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet_length(1 + self.body_len()?, writer)?;
        writer.write_all(&[self.typ().into()])?;
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
            debug!("writing: {}", hex::encode(val));
            val.to_writer(writer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
                panic!("unexpected packet: {:?}", p);
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
}
