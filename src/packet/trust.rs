use std::io::{self, BufRead};

use log::warn;

use crate::errors::Result;
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing_reader::BufReadParsing;
use crate::ser::Serialize;

/// Trust Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-packet-type-id-12>
///
/// Trust packets SHOULD NOT be emitted to output streams that are
/// transferred to other users, and they SHOULD be ignored on any input
/// other than local keyring files.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Trust {
    packet_header: PacketHeader,
}

impl Trust {
    /// Parses a `Trust` packet from the given slice.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        warn!("Trust packet detected, ignoring");
        data.drain()?;

        Ok(Trust { packet_header })
    }
}

impl Serialize for Trust {
    fn to_writer<W: io::Write>(&self, _writer: &mut W) -> Result<()> {
        Ok(())
    }

    fn write_len(&self) -> usize {
        0
    }
}

impl PacketTrait for Trust {
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
        fn write_len(packet: Trust) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(packet: Trust) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = Trust::try_from_reader(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
