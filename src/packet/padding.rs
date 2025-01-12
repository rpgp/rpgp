use std::io;

use bytes::{Buf, Bytes};
use rand::{CryptoRng, RngCore};

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

#[cfg(test)]
use proptest::prelude::*;

/// Padding Packet
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-padding-packet-type-id-21>
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Padding {
    packet_version: Version,
    /// Random data.
    #[debug("{}", hex::encode(data))]
    #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
    data: Bytes,
}

impl Padding {
    /// Parses a `Padding` packet from the given slice.
    pub fn from_buf<B: Buf>(packet_version: Version, mut input: B) -> Result<Self> {
        let data = input.rest();

        Ok(Padding {
            packet_version,
            data,
        })
    }

    /// Create a new padding packet of `size` in bytes.
    pub fn new<R: CryptoRng + RngCore>(mut rng: R, packet_version: Version, size: usize) -> Self {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        Padding {
            packet_version,
            data: data.into(),
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

    fn write_len(&self) -> usize {
        self.data.len()
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
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    use crate::packet::{PacketBody, PacketHeader};
    use crate::types::PacketLength;

    #[test]
    fn test_padding_roundtrip() {
        let packet_raw = hex::decode("d50ec5a293072991628147d72c8f86b7").expect("valid hex");
        let mut to_parse = &mut &packet_raw[..];
        let header = PacketHeader::from_buf(&mut to_parse).expect("parse");

        let PacketLength::Fixed(len) = header.packet_length() else {
            panic!("invalid parse result");
        };
        assert_eq!(to_parse.remaining(), len);
        let rest = to_parse.rest();
        let full_packet =
            PacketBody::from_bytes(header.version(), header.tag(), rest).expect("body parse");

        let PacketBody::Padding(ref packet) = full_packet else {
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

    proptest! {
        #[test]
        fn write_len(padding: Padding) {
            let mut buf = Vec::new();
            padding.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), padding.write_len());
        }


        #[test]
        fn packet_roundtrip(padding: Padding) {
            let mut buf = Vec::new();
            padding.to_writer(&mut buf).unwrap();
            let new_padding = Padding::from_buf(padding.packet_version, &mut &buf[..]).unwrap();
            assert_eq!(padding, new_padding);
        }
    }
}
