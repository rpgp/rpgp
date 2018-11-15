use packet::packet_trait::Packet;
use packet::types::Tag;

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
pub struct SymEncryptedProtectedData(Vec<u8>);

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "invalid input length");
        ensure_eq!(input[0], 0x01, "first bytes must be 0x01");

        Ok(SymEncryptedProtectedData(&input[1..].to_vec()))
    }
}

impl Packet for SymEncryptedProtectedData {
    fn tag(&self) -> Tag {
        Tag::SymEncryptedProtectedData
    }
}
