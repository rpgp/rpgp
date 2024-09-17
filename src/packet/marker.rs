use std::io;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// PGP as UTF-8 octets.
const PGP: [u8; 3] = [0x50, 0x47, 0x50];

/// Marker Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-marker-packet-type-id-10>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    packet_version: Version,
}

impl Marker {
    /// Parses a `Marker` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure_eq!(input, &PGP[..], "invalid input");

        Ok(Marker { packet_version })
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

impl Serialize for Marker {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&PGP[..])?;
        Ok(())
    }
}

impl PacketTrait for Marker {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Marker
    }
}
