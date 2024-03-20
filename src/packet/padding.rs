use std::io;

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
}

impl Padding {
    /// Parses a `Padding` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        // TODO

        Ok(Padding { packet_version })
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

impl Serialize for Padding {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        // TODO

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
