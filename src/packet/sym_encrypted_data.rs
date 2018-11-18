use errors::Result;

/// Symmetrically Encrypted Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.7
#[derive(Debug, Clone)]
pub struct SymEncryptedData(Vec<u8>);

impl SymEncryptedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        Ok(SymEncryptedData(input.to_vec()))
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}
