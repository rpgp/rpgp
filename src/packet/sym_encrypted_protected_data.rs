use packet::packet_trait::Packet;
use packet::types::Tag;

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
pub struct SymEncryptedProtectedData(Vec<u8>);

impl Packet for SymEncryptedProtectedData {
    fn tag(&self) -> Tag {
        Tag::SymEncryptedProtectedData
    }
}
