use std::io;

use byteorder::{BigEndian, WriteBytesExt};

use errors::Result;
use packet::signature::types::*;
use ser::Serialize;
use util::write_mpi;

impl Serialize for Signature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => self.to_writer_v3(writer),
            SignatureVersion::V4 | SignatureVersion::V5 => self.to_writer_v4(writer),
        }
    }
}

fn write_packet_len(len: usize, writer: &mut impl io::Write) -> Result<()> {
    println!("write packet len {}", len);
    if len < 192 {
        println!("< 192");
        writer.write_all(&[len as u8])?;
    } else if len < 8384 {
        println!("< 8384");
        writer.write_all(&[((len - 192) / 255 + 192) as u8, ((len - 192) % 255) as u8])?;
    } else {
        println!("large");
        writer.write_u32::<BigEndian>(len as u32)?;
    }

    Ok(())
}

impl Subpacket {
    fn body_to_writer(&self, writer: &mut impl io::Write) -> Result<()> {
        match self {
            Subpacket::SignatureCreationTime(t) => {
                writer.write_u32::<BigEndian>(t.timestamp() as u32)?;
            }
            Subpacket::SignatureExpirationTime(_) => unimplemented!(),
            Subpacket::KeyExpirationTime(_) => unimplemented!(),
            Subpacket::Issuer(id) => {
                writer.write_all(id.as_ref())?;
            }
            Subpacket::PreferredSymmetricAlgorithms(_) => unimplemented!(),
            Subpacket::PreferredHashAlgorithms(_) => unimplemented!(),
            Subpacket::PreferredCompressionAlgorithms(_) => unimplemented!(),
            Subpacket::KeyServerPreferences(_) => unimplemented!(),
            Subpacket::KeyFlags(_) => unimplemented!(),
            Subpacket::Features(_) => unimplemented!(),
            Subpacket::RevocationReason(_, _) => unimplemented!(),
            Subpacket::IsPrimary(_) => unimplemented!(),
            Subpacket::Revocable(_) => unimplemented!(),
            Subpacket::EmbeddedSignature(_) => unimplemented!(),
            Subpacket::PreferredKeyServer(_) => unimplemented!(),
            Subpacket::Notation(_) => unimplemented!(),
            Subpacket::RevocationKey(_) => unimplemented!(),
            Subpacket::SignersUserID(body) => {
                writer.write_all(body.as_ref())?;
            }
            Subpacket::PolicyURI(_) => unimplemented!(),
            Subpacket::TrustSignature(_, _) => unimplemented!(),
            Subpacket::RegularExpression(_) => unimplemented!(),
            Subpacket::ExportableCertification(_) => unimplemented!(),
            Subpacket::Experimental(_) => unimplemented!(),
        }

        Ok(())
    }

    fn body_len(&self) -> usize {
        match self {
            Subpacket::SignatureCreationTime(_) => 4,
            Subpacket::SignatureExpirationTime(_) => unimplemented!(),
            Subpacket::KeyExpirationTime(_) => unimplemented!(),
            Subpacket::Issuer(_) => 8,
            Subpacket::PreferredSymmetricAlgorithms(_) => unimplemented!(),
            Subpacket::PreferredHashAlgorithms(_) => unimplemented!(),
            Subpacket::PreferredCompressionAlgorithms(_) => unimplemented!(),
            Subpacket::KeyServerPreferences(_) => unimplemented!(),
            Subpacket::KeyFlags(_) => unimplemented!(),
            Subpacket::Features(_) => unimplemented!(),
            Subpacket::RevocationReason(_, _) => unimplemented!(),
            Subpacket::IsPrimary(_) => unimplemented!(),
            Subpacket::Revocable(_) => unimplemented!(),
            Subpacket::EmbeddedSignature(_) => unimplemented!(),
            Subpacket::PreferredKeyServer(_) => unimplemented!(),
            Subpacket::Notation(_) => unimplemented!(),
            Subpacket::RevocationKey(_) => unimplemented!(),
            Subpacket::SignersUserID(body) => {
                let bytes: &[u8] = body.as_ref();
                bytes.len()
            }
            Subpacket::PolicyURI(_) => unimplemented!(),
            Subpacket::TrustSignature(_, _) => unimplemented!(),
            Subpacket::RegularExpression(_) => unimplemented!(),
            Subpacket::ExportableCertification(_) => unimplemented!(),
            Subpacket::Experimental(_) => unimplemented!(),
        }
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
            Subpacket::Experimental(_) => SubpacketType::Experimental,
        }
    }
}

impl Serialize for Subpacket {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        println!("writing subpacket {:?}", self.typ());
        write_packet_len(1 + self.body_len(), writer)?;
        writer.write_all(&[self.typ() as u8])?;
        self.body_to_writer(writer)?;

        Ok(())
    }
}

impl Signature {
    /// Serializes a v2or v3 signature.
    fn to_writer_v3<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!()
    }

    /// Serializes a v4 or v5 signature.
    fn to_writer_v4<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[
            // version
            self.version as u8,
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

        // signed hash value
        writer.write_all(&self.signed_hash_value)?;

        // the actual signature
        for val in &self.signature {
            write_mpi(val, writer)?;
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

    use de::Deserialize;
    use packet::{Packet, PacketParser};
    use ser::Serialize;

    fn test_roundtrip(name: &str) {
        let f = File::open(Path::new("./tests/openpgp/samplemsgs").join(name)).unwrap();

        let packets: Vec<Packet> = PacketParser::new(f).collect::<Result<_>>().unwrap();
        let mut serialized = Vec::new();

        for p in &packets {
            if let Packet::Signature(sig) = p {
                println!("got sig: {:?}", sig);
            } else {
                panic!("unexpected packet: {:?}", p);
            };

            p.to_writer(&mut serialized).unwrap();
        }

        let bytes = {
            let mut f = File::open(Path::new("./tests/openpgp/samplemsgs").join(name)).unwrap();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();
            bytes
        };

        // Note: for now we ignore the top level two bytes, as we write new style packets
        // but some of the sources are old style packets.
        assert_eq!(&bytes[0..], &serialized[0..], "failed to roundtrip");
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
