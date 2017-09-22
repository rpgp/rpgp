use enum_primitive::FromPrimitive;
use util::{u8_as_usize, u16_as_usize, u32_as_usize};

pub mod types;
pub mod tags;

/// Represents a Packet. A packet is the record structure used to encode a chunk of data in OpenPGP.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet {
    /// Indicator if this is an old or new versioned packet
    pub version: Version,
    /// Denotes the type of data this packet holds
    pub tag: Tag,
    /// The raw bytes of the packet
    pub body: Vec<u8>,
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Tag {
    /// Public-Key Encrypted Session Key Packet
    PublicKeyEncryptedSessionKey = 1,
    /// Signature Packet
    Signature = 2,
    /// Symmetric-Key Encrypted Session Key Packet
    SymKeyEncryptedSessionKey = 3,
    /// One-Pass Signature Packet
    OnePassSignature = 4,
    /// Secret-Key Packet
    SecretKey = 5,
    /// Public-Key Packet
    PublicKey = 6,
    /// Secret-Subkey Packet
    SecretSubkey = 7,
    /// Compressed Data Packet
    CompressedData = 8,
    /// Symmetrically Encrypted Data Packet
    SymetricEncryptedData = 9,
    /// Marker Packet
    Marker = 10,
    /// Literal Data Packet
    Literal = 11,
    /// Trust Packet
    Trust = 12,
    /// User ID Packet
    UserID = 13,
    /// Public-Subkey Packet
    PublicSubkey = 14,
    /// User Attribute Packet
    UserAttribute = 17,
    /// Sym. Encrypted and Integrity Protected Data Packet
    SymEncryptedProtectedData = 18,
    /// Modification Detection Code Packet    
    ModDetectionCode = 19,       
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Version {
    /// Old Packet Format
    Old = 0,
    /// New Packet Format
    New = 1,
}
}

/// Parses an old format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
named!(old_packet_header((&[u8], usize)) -> (Version, Tag, usize), do_parse!(
    // Version: 0
       ver: map_opt!(tag_bits!(u8, 1, 0), Version::from_u8)
    // Packet Tag
    >> tag: map_opt!(take_bits!(u8, 4), Tag::from_u8)
    // Packet Length Type
    >> len: switch!(take_bits!(u8, 2),
        // One-Octet Lengths
        0 => map!(take_bits!(u8, 8), u8_as_usize)    |
        // Two-Octet Lengths
        1 => map!(take_bits!(u16, 16), u16_as_usize) |
        // Four-Octet Lengths
        2 => map!(take_bits!(u32, 32), u32_as_usize)
        // TODO: Indeterminate length
        // 3 => ?
    ) 
    >> ((ver, tag, len))
));

/// Parses a new format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
named!(new_packet_header((&[u8], usize)) -> (Version, Tag, usize), dbg!(do_parse!(
    // Version: 1
        ver: map_opt!(tag_bits!(u8, 1, 1), Version::from_u8)
    // Packet Tag
    >>  tag: map_opt!(take_bits!(u8, 6), Tag::from_u8)
    >> olen: take_bits!(u8, 8)
    >>  len: switch!(value!(olen),
        // One-Octet Lengths
        0...191   => value!(olen as usize) |
        // Two-Octet Lengths
        192...223 => map!(take_bits!(u8, 8), |a| {
            ((olen as usize - 192) << 8) + 192 + a as usize
        }) |
        // Five-Octet Lengths
        255       => map!(take_bits!(u32, 32), u32_as_usize)
        // Partial Body Lengths
        // TODO: 224...254 => value!(1)
    )
    >> ((ver, tag, len))
)));

/// Parse Packet Headers
/// ref: https://tools.ietf.org/html/rfc4880.html#section-4.2
named!(pub packet_parser<Packet>, dbg_dmp!(bits!(do_parse!(
    // First bit is always 1
             tag_bits!(u8, 1, 1)
    >> head: alt_complete!(new_packet_header | old_packet_header) 
    >> body: bytes!(take!(head.2))
    >> (Packet{
        version: head.0,
        tag: head.1,
        body: body.to_vec(),
    })
))));
