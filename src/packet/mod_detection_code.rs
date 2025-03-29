use std::io::{self, BufRead};

use crate::errors::Result;
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing_reader::BufReadParsing;
use crate::ser::Serialize;

/// Modification Detection Code Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#version-one-seipd>
///
/// Also see <https://www.rfc-editor.org/rfc/rfc9580.html#name-terminology-changes>:
///
/// "Modification Detection Code" or "MDC" was originally described as a distinct packet
/// (Packet Type ID 19), and its corresponding flag in the Features signature subpacket
/// (Section 5.2.3.32) was known as "Modification Detection".
/// It is now described as an intrinsic part of v1 SEIPD (Section 5.13.1), and the same
/// corresponding flag is known as "Version 1 Symmetrically Encrypted and Integrity Protected
/// Data packet".
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ModDetectionCode {
    packet_header: PacketHeader,
    /// 20 byte SHA1 hash of the preceding plaintext data.
    #[debug("{}", hex::encode(hash))]
    hash: [u8; 20],
}

impl ModDetectionCode {
    /// Parses a `ModDetectionCode` packet.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let hash = input.read_array::<20>()?;

        Ok(ModDetectionCode {
            packet_header,
            hash,
        })
    }
}

impl Serialize for ModDetectionCode {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.hash[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.hash.len()
    }
}

impl PacketTrait for ModDetectionCode {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn write_len(packet: ModDetectionCode) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(packet: ModDetectionCode) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = ModDetectionCode::try_from_reader(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
