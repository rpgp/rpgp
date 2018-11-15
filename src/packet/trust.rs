use packet::packet_trait::Packet;
use packet::types::Tag;

/// Trust Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.10
/// Trust packets SHOULD NOT be emitted to output streams that are
/// transferred to other users, and they SHOULD be ignored on any input
/// other than local keyring files.
pub struct Trust;

impl Packet for Trust {
    fn tag(&self) -> Tag {
        Tag::Trust
    }
}

impl Trust {
    fn new() -> Self {
        Trust
    }
}
