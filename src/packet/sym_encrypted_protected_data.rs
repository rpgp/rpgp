use std::{fmt, io};

use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{Tag, Version};

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq)]
pub struct SymEncryptedProtectedData {
    packet_version: Version,
    data: Vec<u8>,
}

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "invalid input length");
        ensure_eq!(input[0], 0x01, "first bytes must be 0x01");

        Ok(SymEncryptedProtectedData {
            data: input[1..].to_vec(),
            packet_version,
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for SymEncryptedProtectedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[0x01])?;
        writer.write_all(&self.data)?;

        Ok(())
    }
}

impl PacketTrait for SymEncryptedProtectedData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::SymEncryptedProtectedData
    }
}

impl fmt::Debug for SymEncryptedProtectedData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SymEncryptedProtectedData")
            .field("packet_version", &self.packet_version)
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}
