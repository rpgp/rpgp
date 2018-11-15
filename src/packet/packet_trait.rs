use packet::types::Tag;

pub trait Packet {
    /// Returns the tag for this packet type.
    fn tag(&self) -> Tag;
}
