use std::str;

use packet::packet_trait::Packet;
use packet::types::Tag;

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
pub struct UserId(String);

impl UserId {
    /// Parses a `UserId` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let id = str::from_utf8(input)?;

        Ok(UserId(id))
    }
}

impl Packet for UserId {
    fn tag(&self) -> Tag {
        Tag::UserID
    }
}
