use std::io;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

use super::Span;

/// Modification Detection Code Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.14
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModDetectionCode {
    packet_version: Version,
    /// 20 byte SHA1 hash of the preceeding plaintext data.
    hash: [u8; 20],
}

impl ModDetectionCode {
    /// Parses a `ModDetectionCode` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: Span<'_>) -> Result<Self> {
        ensure_eq!(input.len(), 20, "invalid input len");

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&input);

        Ok(ModDetectionCode {
            packet_version,
            hash,
        })
    }
}

impl Serialize for ModDetectionCode {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.hash[..])?;
        Ok(())
    }
}

impl PacketTrait for ModDetectionCode {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::ModDetectionCode
    }
}
