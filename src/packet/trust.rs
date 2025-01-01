use std::io;

use log::warn;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Trust Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-packet-type-id-12>
///
/// Trust packets SHOULD NOT be emitted to output streams that are
/// transferred to other users, and they SHOULD be ignored on any input
/// other than local keyring files.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Trust {
    packet_version: Version,
}

impl Trust {
    /// Parses a `Trust` packet from the given slice.
    pub fn from_slice(packet_version: Version, _: &[u8]) -> Result<Self> {
        warn!("Trust packet detected, ignoring");

        Ok(Trust { packet_version })
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
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn write_len(trust: Trust) {
            let mut buf = Vec::new();
            trust.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), trust.write_len());
        }

        #[test]
        fn packet_roundtrip(trust: Trust) {
            let mut buf = Vec::new();
            trust.to_writer(&mut buf).unwrap();
            let new_trust = Trust::from_slice(trust.packet_version, &buf).unwrap();
            assert_eq!(trust, new_trust);
        }
    }
}
