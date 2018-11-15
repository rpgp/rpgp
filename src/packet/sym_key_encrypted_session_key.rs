use crypto::sym::SymmetricKeyAlgorithm;
use packet::packet_trait::Packet;
use packet::types::{StringToKeyType, Tag};

/// Symmetric-Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.3
pub struct SymKeyEncryptedSessionKey {
    sym_algorithm: SymmetricKeyAlgorithm,
    s2k: StringToKeyType,
    encrypted_key: Option<Vec<u8>>,
}

impl Packet for SymKeyEncryptedSessionKey {
    fn tag(&self) -> Tag {
        Tag::SymKeyEncryptedSessionKey
    }
}
