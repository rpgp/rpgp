use std::{fmt, io};

use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{Tag, Version};

/// Symmetrically Encrypted Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.7
#[derive(Clone, PartialEq, Eq)]
pub struct SymEncryptedData {
    packet_version: Version,
    data: Vec<u8>,
}

impl SymEncryptedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        Ok(SymEncryptedData {
            packet_version,
            data: input.to_vec(),
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for SymEncryptedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }
}

impl PacketTrait for SymEncryptedData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::SymEncryptedData
    }
}

impl fmt::Debug for SymEncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SymEncryptedData")
            .field("packet_version", &self.packet_version)
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}
