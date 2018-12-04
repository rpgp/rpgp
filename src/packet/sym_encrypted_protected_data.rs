use errors::Result;
use types::Version;

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Debug, Clone)]
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

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}
