use enum_primitive::FromPrimitive;
use util::{u8_as_usize, u16_as_usize, u32_as_usize};
use std::io::Read;
use circular::Buffer;
use nom::{self, Needed, Offset};

use errors::Result;
    
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
named!(old_packet_header(&[u8]) -> (Version, Tag, usize), bits!(do_parse!(
    // First bit is always 1
            tag_bits!(u8, 1, 1)
    // Version: 0
    >> ver: map_opt!(tag_bits!(u8, 1, 0), Version::from_u8)
    // Packet Tag
    >> tag: map_opt!(take_bits!(u8, 4), Tag::from_u8)
    // Packet Length Type
    >> len_type: take_bits!(u8, 2)
    >> len: switch!(value!(len_type),
        // One-Octet Lengths
        0 => map!(take_bits!(u8, 8), u8_as_usize)    |
        // Two-Octet Lengths
        1 => map!(take_bits!(u16, 16), u16_as_usize) |
        // Four-Octet Lengths
        2 => map!(take_bits!(u32, 32), u32_as_usize)
        // TODO: Indeterminate length
        // 3 => unimplemented!("indeterminate length")
    )
        >> (ver, tag, len)
)));

/// Parses a new format packet header
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
named!(new_packet_header(&[u8]) -> (Version, Tag, usize), bits!(do_parse!(
    // First bit is always 1
             tag_bits!(u8, 1, 1)
    // Version: 1
    >>  ver: map_opt!(tag_bits!(u8, 1, 1), Version::from_u8)
    // Packet Tag
    >>  tag: map_opt!(take_bits!(u8, 6), Tag::from_u8)
    >> olen: take_bits!(u8, 8)
    >>  len: switch!(value!(olen),
        // One-Octet Lengths
        0...191   => value!(olen as usize) |
        // Two-Octet Lengths
        192...254 => map!(take_bits!(u8, 8), |a| {
            ((olen as usize - 192) << 8) + 192 + a as usize
        }) |
        // Five-Octet Lengths
        255       => map!(take_bits!(u32, 32), u32_as_usize)
        // Partial Body Lengths
        // TODO: 224...254 => value!(1)
    )
    >> (ver, tag, len)
)));

/// Parse Packet Headers
/// ref: https://tools.ietf.org/html/rfc4880.html#section-4.2
named!(pub packet_parser<Packet>, do_parse!(
       head: alt!(new_packet_header | old_packet_header) 
    >> body: take!(head.2)
    >> (Packet{
            version: head.0,
            tag: head.1,
            body: body.to_vec(),
        })
));

/// Parse packets, in a streaming fashion from the given reader.
pub fn packets_parser(mut input: impl Read) -> Result<Vec<Packet>> {
    // maximum size of our buffer
    let max_capacity = 1024 * 1024 * 1024;
    // the inital capacity of our buffer
    // TODO: use a better value than a random guess
    let mut capacity = 1024;
    let mut b = Buffer::with_capacity(capacity);

    let mut packets = Vec::new();

    loop {
        // read some data
        let sz = input.read(b.space()).unwrap();
        b.fill(sz);

        // if there's no more available data in the buffer after a write, that means we reached
        // the end of the input
        if b.available_data() == 0 {
            break;
        }

        let needed: Option<Needed>;

        loop {
            let length = {
                match packet_parser(b.data()) {
                    Ok((remaining, p)) => {
                        packets.push(p);
                        b.data().offset(remaining)
                    }
                    Err(err) => match err {
                        nom::Err::Incomplete(n) => {
                            needed = Some(n);
                            break;
                        }
                        _ => return Err(err.into())
                    },
                }
            };
            
            b.consume(length);
        }

        // if the parser returned `Incomplete`, and it needs more data than the buffer can hold, we grow the buffer.
        if let Some(Needed::Size(sz)) = needed {
            if sz > b.capacity() && capacity * 2 < max_capacity {
                capacity *= 2;
                b.grow(capacity);
            }
        }
    }

    Ok(packets)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;
    
    #[test]
    fn test_packets_parser() {
        let p = Path::new("./tests/sks-dump/0000.pgp");
        let file = File::open(p).unwrap();

        let packets = packets_parser(file).unwrap();
        assert_eq!(packets.len(), 141945);
    }
}
