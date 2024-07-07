use std::io;

use log::warn;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Trust Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.10
/// Trust packets SHOULD NOT be emitted to output streams that are
/// transferred to other users, and they SHOULD be ignored on any input
/// other than local keyring files.
#[derive(Debug, PartialEq, Eq)]
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
}

impl PacketTrait for Trust {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Trust
    }
}
