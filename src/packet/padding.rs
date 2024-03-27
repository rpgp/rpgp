use std::io;

use rand::{CryptoRng, RngCore};

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Padding Packet
///
/// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-padding-packet-type-id-21
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Padding {
    packet_version: Version,
    /// Random data.
    data: Vec<u8>,
}

impl Padding {
    /// Parses a `Padding` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        Ok(Padding {
            packet_version,
            data: input.to_vec(),
        })
    }

    /// Create a new padding packet of `size` in bytes.
    pub fn new<R: CryptoRng + RngCore>(mut rng: R, packet_version: Version, size: usize) -> Self {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        Padding {
            packet_version,
            data,
        }
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

impl Serialize for Padding {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.data)?;

        Ok(())
    }
}

impl PacketTrait for Padding {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Padding
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    use super::super::single;
    use crate::packet::single::ParseResult;
    use crate::packet::Packet;

    #[test]
    fn test_padding_roundtrip() {
        let packet_raw = hex::decode("d50ec5a293072991628147d72c8f86b7").expect("valid hex");
        let (rest, (version, tag, _plen, body)) = single::parser(&packet_raw).expect("parse");
        assert!(rest.is_empty());

        let ParseResult::Fixed(body) = body else {
            panic!("invalid parse result");
        };
        let full_packet = single::body_parser(version, tag, body).expect("body parse");

        let Packet::Padding(ref packet) = full_packet else {
            panic!("invalid packet: {:?}", full_packet);
        };
        assert_eq!(
            packet.data,
            hex::decode("c5a293072991628147d72c8f86b7").expect("valid hex")
        );

        // encode
        let encoded = full_packet.to_bytes().expect("encode");
        assert_eq!(encoded, packet_raw);
    }

    #[test]
    fn test_padding_new() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let packet = Padding::new(&mut rng, Version::New, 20);
        assert_eq!(packet.data.len(), 20);

        let encoded = packet.to_bytes().expect("encode");
        assert_eq!(encoded, packet.data);
    }
}
