use errors::Result;

/// Modification Detection Code Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.14
#[derive(Debug, Clone)]
pub struct ModDetectionCode {
    /// 20 byte SHA1 hash of the preceeding plaintext data.
    hash: [u8; 20],
}

impl ModDetectionCode {
    /// Parses a `ModDetectionCode` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        ensure_eq!(input.len(), 20, "invalid input len");

        let mut hash = [0u8; 20];
        hash.copy_from_slice(input);

        Ok(ModDetectionCode { hash })
    }
}
