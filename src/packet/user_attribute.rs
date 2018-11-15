use packet::packet_trait::Packet;
use packet::types::Tag;
use packet::Signature;

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserAttribute {
    pub attr: UserAttributeType,
    pub signatures: Vec<Signature>,
}

impl Packet for UserAttribute {
    fn tag(&self) -> Tag {
        Tag::UserAttribute
    }
}

impl UserAttribute {
    pub fn new(attr: UserAttributeType, signatures: Vec<Signature>) -> Self {
        UserAttribute { attr, signatures }
    }
}

/// Available user attribute types
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UserAttributeType {
    Image(Vec<u8>),
    Unknown((u8, Vec<u8>)),
}

impl UserAttributeType {
    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttributeType::Image(_) => 1,
            UserAttributeType::Unknown((typ, _)) => typ,
        }
    }
}
