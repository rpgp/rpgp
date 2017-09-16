use nom::IResult;
// use openssl::rsa::Rsa;
// use openssl::bn::BigNum;
use enum_primitive::FromPrimitive;
use std::str;

use packet::{Packet, packet_parser};
use armor;
use util::mpi;

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign) [HAC]
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only) [HAC]
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only) [HAC]
    RSASign = 3,
    /// Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    ELSign = 16,
    /// DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    DSA = 17,
    /// RESERVED: Elliptic Curve
    EC = 18,
    /// RESERVED: ECDSA
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    EL = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
}
}

named!(rsa_fields<(&[u8], &[u8])>, do_parse!(
    n: mpi >>
    e: mpi >>
    ((n, e))
));


named!(packets_parser<Vec<Packet>>, many1!(packet_parser));

named!(public_key_body<Option<u8>>, bits!(do_parse!(
    key_ver: take_bits!(u8, 8) >>
    details: switch!(
        value!(key_ver), 
        2...3 => do_parse!(
            key_time: take_bits!(u32, 32) >>
                exp: take_bits!(u16, 16)      >>
                alg: map_opt!(
                    take_bits!(u8, 8),
                    PublicKeyAlgorithm::from_u8
                ) >>
                ((key_time, exp, alg, (&b""[..], &b""[..])))
        ) |
        4 => do_parse!(
            key_time: take_bits!(u32, 32) >>
                alg: map_opt!(
                    take_bits!(u8, 8),
                    PublicKeyAlgorithm::from_u8
                ) >>
                fields: bytes!(switch!(
                    value!(&alg), 
                    &PublicKeyAlgorithm::RSA => call!(rsa_fields) |
                    &PublicKeyAlgorithm::RSAEncrypt => call!(rsa_fields) |
                    &PublicKeyAlgorithm::RSASign => call!(rsa_fields) 
                )) >> 
                ({
                    let (n, e) = fields;
                    let bits = n.len() * 8;
                    println!("fields: {} {}", bits, e.len());
                    
                    (key_time, 0, alg, fields)
                })
        ) 
    ) >>
    ({ Some(key_ver) })
)));

named_args!(
    packet_body_parser(tag: u8) <Option<u8>>,
    switch!(value!(tag),
    // Public Key
    6 => call!(public_key_body) |
    _ => value!(None)
));


pub fn parse<'a>(msg: &'a [u8]) -> IResult<&[u8], armor::Block<'a>> {
    armor::parse(msg).map(|(typ, headers, body)| {
        // TODO: Proper error handling
        let (_, packets) = packets_parser(body.as_slice()).unwrap();
        armor::Block {
            typ: typ,
            headers: headers,
            packets: packets,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet;

    #[test]
    fn test_parse() {
        let raw = include_bytes!("../tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc");
        let (_, block) = parse(raw).unwrap();
        assert_eq!(block.typ, armor::BlockType::PublicKey);
        assert_eq!(block.packets.len(), 9);
        assert_eq!(block.packets[0].version, packet::Version::Old);
        assert_eq!(block.packets[0].tag, packet::Tag::PublicKey);
    }
}
