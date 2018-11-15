use packet::packet_trait::Packet;
use packet::types::Tag;

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
pub struct UserId(String);

impl Packet for UserId {
    fn tag(&self) -> Tag {
        Tag::UserID
    }
}
