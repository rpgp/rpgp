use errors::Result;
use types::Version;

/// Symmetrically Encrypted Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.7
#[derive(Debug, Clone)]
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

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}
