use nom::{self, IResult, AsChar, digit, line_ending, not_line_ending, is_alphanumeric};
use std::str;
// use openssl::rsa::Rsa;
// use openssl::bn::BigNum;
use header::collect_into_string;
use std::collections::HashMap;
use std::ops::{Range, RangeFrom, RangeTo};
use crc24;
use base64;
use byteorder::{ByteOrder, BigEndian};
use enum_primitive::FromPrimitive;
use packet::{Packet, packet_parser};

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

#[inline]
fn is_base64_token(c: char) -> bool {
    is_alphanumeric(c as u8) || c == '/' || c == '+'
}

/// Parse Multi Precision Integers as described in
/// https://tools.ietf.org/html/rfc4880.html#section-3.2
named!(
    mpi<&[u8]>,
    do_parse!(
    len: u16!(nom::Endianness::Big) >>
    val: take!((len + 7) >> 3) >>
    (val)
)
);

/// Recognizes one or more body tokens
fn base64_token<T>(input: T) -> IResult<T, T>
where
    T: nom::Slice<Range<usize>> + nom::Slice<RangeFrom<usize>> + nom::Slice<RangeTo<usize>>,
    T: nom::InputIter + nom::InputLength,
    <T as nom::InputIter>::Item: AsChar,
{
    let input_length = input.input_len();
    if input_length == 0 {
        return IResult::Incomplete(nom::Needed::Unknown);
    }

    for (idx, item) in input.iter_indices() {
        let item = item.as_char();
        if !is_base64_token(item) {
            if idx == 0 {
                return IResult::Error(error_position!(nom::ErrorKind::AlphaNumeric, input));
            } else {
                return IResult::Done(input.slice(idx..), input.slice(0..idx));
            }
        }
    }
    IResult::Done(input.slice(input_length..), input)
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArmorBlock<'a> {
    typ: ArmorBlockType,
    headers: HashMap<&'a str, &'a str>,
    packets: Vec<Packet>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ArmorBlockType {
    PublicKey,
    PrivateKey,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
}

named!(armor_header_sep, tag!("-----"));

named!(armor_header_type<ArmorBlockType>, alt_complete!(
    map!(
        tag!("PGP PUBLIC KEY BLOCK"),
        |_| ArmorBlockType::PublicKey
    ) |
    map!(
        tag!("PGP PRIVATE KEY BLOCK"),
        |_| ArmorBlockType::PrivateKey
    ) |
    do_parse!(
           tag!("PGP MESSAGE, PART ") >>
        x: map_res!(digit, str::from_utf8) >>
        y: opt!(map_res!(preceded!(tag!("/"), digit), str::from_utf8)) >>
        ({
            // unwraps are safe, as the parser already determined that this is a digit.
            
            let x: usize = x.parse().unwrap();
            let y: usize = y.map(|s| s.parse().unwrap()).unwrap_or(0);
            
            ArmorBlockType::MultiPartMessage(x, y)
        })    
    ) |
    map!(
        tag!("PGP MESSAGE"),
        |_| ArmorBlockType::Message
    ) |
    map!(
        tag!("PGP SIGNATURE"),
        |_| ArmorBlockType::Signature
    )
));

named!(
    armor_header_line<ArmorBlockType>,
    do_parse!(
         armor_header_sep  >>
         tag!("BEGIN ")    >>
    typ: armor_header_type >>
         armor_header_sep  >>
         line_ending       >>
    (typ)
)
);

named!(armor_footer_line<ArmorBlockType>, do_parse!(
         armor_header_sep  >>
         tag!("END ")      >>
    typ: armor_header_type >>
         armor_header_sep  >>
         alt_complete!(line_ending | eof!()) >>
    (typ)
)
);

named!(armor_headers<HashMap<&str, &str>>, map!(separated_list_complete!(
    line_ending, 
    separated_pair!(
        map_res!(take_until!(": "), str::from_utf8),
        tag!(": "),
        map_res!(not_line_ending, str::from_utf8)
    )
), |v| v.iter().map(|p| *p).collect()));

named!(armor_header<(ArmorBlockType, HashMap<&str, &str>)>, do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers     >>
    ((typ, headers))
));

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



named!(armor_block<(ArmorBlockType, HashMap<&str, &str>, Vec<u8>)>, do_parse!(
    header: armor_header >>
            many0!(line_ending) >>
    inner:  map!(separated_list_complete!(
              line_ending, base64_token
            ), collect_into_string) >>
            opt!(line_ending) >>
    check:  preceded!(tag!("="), take!(4)) >>
            many1!(line_ending) >>
    footer: armor_footer_line >>
    ({
        if header.0 != footer {
            // TODO: proper error handling
            panic!("Non matching armor wrappers {:?} != {:?}", header.0, footer);
        }

        // TODO: proper error handling
        let decoded = base64::decode_config(&inner, base64::MIME).expect("Invalid base64 encoding");
        
        let check_new = crc24::hash_raw(decoded.as_slice());

        // TODO: proper error handling
        let check_decoded = base64::decode_config(check, base64::MIME).expect("Invalid base64 encoding checksum");
        let mut check_decoded_buf = [0; 4];
        let mut i = check_decoded.len();
        for a in check_decoded.iter().rev() {
            check_decoded_buf[i] = *a;
            i -= 1;
        }

        let check_u32 = BigEndian::read_u32(&check_decoded_buf);
        if check_new != check_u32 {
            // TODO: proper error handling
            panic!("Corrupted data, missmatch checksum {} != {}", check_new, check_u32);
        }
        
        (header.0, header.1, decoded)
    })
));

pub fn parse<'a>(msg: &'a [u8]) -> IResult<&[u8], ArmorBlock<'a>> {
    armor_block(msg).map(|(typ, headers, body)| {
        // TODO: Proper error handling
        let (_, packets) = packets_parser(body.as_slice()).unwrap();
        ArmorBlock {
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
    fn test_armor_header_line() {
        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE-----\n"[..]), IResult::Done(&b""[..], ArmorBlockType::Message));

        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 3/14-----\n"[..]), IResult::Done(&b""[..], ArmorBlockType::MultiPartMessage(3, 14)));

        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 14-----\n"[..]), IResult::Done(&b""[..], ArmorBlockType::MultiPartMessage(14, 0)));
    }

    #[test]
    fn test_armor_headers() {
        let mut map = HashMap::new();
        map.insert("Version", "12");
        map.insert("special-stuff", "cool12.0");
        map.insert("some:colon", "with:me");

        assert_eq!(armor_headers(&b"Version: 12\r\nspecial-stuff: cool12.0\r\nsome:colon: with:me"[..]), IResult::Done(&b""[..], map));
    }

    #[test]
    fn test_armor_header() {
        let mut map = HashMap::new();
        map.insert("Version", "1.0");
        map.insert("Mode", "Test");

        assert_eq!(armor_header(&b"-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test"[..]), IResult::Done(&b""[..], (ArmorBlockType::Message, map)));
    }

    #[test]
    fn test_parse() {
        let raw = include_bytes!("../tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc");
        let res = parse(raw);
        if let IResult::Done(_, block) = res {
            assert_eq!(block.typ, ArmorBlockType::PublicKey);
            assert_eq!(block.packets.len(), 9);
            assert_eq!(block.packets[0].version, packet::Version::Old);
            assert_eq!(block.packets[0].tag, packet::Tag::PublicKey);
        } else {
            panic!("failed to parse: {:?}", res);
        }
    }

    #[test]
    fn test_mpi() {
        assert_eq!(mpi(&[0x00, 0x01, 0x01][..]), IResult::Done(&b""[..], &[1][..]));
        assert_eq!(mpi(&[0x00, 0x09, 0x01, 0xFF][..]), IResult::Done(&b""[..], &[0x01, 0xFF][..]));
    }
}
