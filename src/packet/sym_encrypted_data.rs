use packet::packet_trait::Packet;
use packet::types::Tag;

/// Symmetrically Encrypted Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.7
pub struct SymEncryptedData(Vec<u8>);

impl Packet for SymEncryptedData {
    fn tag(&self) -> Tag {
        Tag::SymEncryptedData
    }
}
