use errors::Result;

/// Trust Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.10
/// Trust packets SHOULD NOT be emitted to output streams that are
/// transferred to other users, and they SHOULD be ignored on any input
/// other than local keyring files.
#[derive(Debug)]
pub struct Trust {}

impl Trust {
    /// Parses a `Trust` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        warn!("Trust packet detected, ignoring");

        Ok(Trust {})
    }
}
