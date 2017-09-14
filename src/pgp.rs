use nom::{self, IResult, AsChar, digit, line_ending, not_line_ending, is_alphanumeric, be_u8};
use std::str;
use openssl::rsa::Rsa;
// use openssl::bn::BigNum;
use header::collect_into_string;
use std::collections::HashMap;
use std::ops::{Range, RangeFrom, RangeTo};
use crc24;
use base64;
use byteorder::{ByteOrder, BigEndian};

#[inline]
fn is_base64_token(c: char) -> bool {
    is_alphanumeric(c as u8) || c == '/' || c == '+'
}

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
pub enum ArmorBlock<'a> {
    PublicKey {
        headers: HashMap<&'a str, &'a str>,
        version: u8,
    },
    PrivateKey {},
    Message {},
    Signature {},
    // TODO: what about MultiPartMessage?
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

named!(public_key_parser<u8>, bits!(do_parse!(
    // Packet Header - First octet
         tag_bits!(u8, 1, 1) >>
    top: alt_complete!(
             // New Packet Style
             do_parse!(
                 // Version 
                      tag_bits!(u8, 1, 1) >>
                 // Packet Tag
                 tag: take_bits!(u8, 6)   >>
                 ((1, tag, None))
             ) |
             // Old Packet Style
             do_parse!(
                 // Version
                     tag_bits!(u8, 1, 0) >>
                 // Packet Tag
                 tag: take_bits!(u8, 4)   >>
                 // Packet Length 
                 len: take_bits!(u8, 2)   >>
                 ((0, tag, Some(len)))
             )
    ) >> 
    ver: take_bits!(u8, 8) >>
    ({
        println!("header: {:?}", top);
        ver
    })
)));

fn public_key<'a, 'b>(headers: HashMap<&'b str, &'b str>, msg: &'a [u8]) -> Option<ArmorBlock<'b>> {
    println!("start: {:#010b} {:#010b} {:#010b}", msg[0], msg[1], msg[2]);
    match public_key_parser(msg) {
        IResult::Done(rest, version) => {
            Some(ArmorBlock::PublicKey {
                headers: headers,
                version: version,
            })
        }
        _ => None,
    }
}

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
            // TODO: proper error handlign
            panic!("Non matching armor wrappers {:?} != {:?}", header.0, footer);
        }

        // TODO: proper error handling
        let decoded = base64::decode_config(&inner, base64::MIME).expect("Invalid base64 encoding");
        
        let check_new = crc24::hash_raw(decoded.as_slice());

        // TODO: proper error handlign
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


pub fn parse(msg: &[u8]) -> IResult<&[u8], ArmorBlock> {
    let block = armor_block(msg);

    match block {
        IResult::Done(_, (typ, headers, inner)) => {
            match typ {
                ArmorBlockType::PublicKey => {
                    match public_key(headers, inner.as_slice()) {
                        Some(key) => IResult::Done(&b""[..], key),
                        None => unimplemented!(),
                    }
                }
                _ => unimplemented!(),
            }
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(size) => IResult::Incomplete(size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        if let IResult::Done(rest, key) = res {
            let mut headers = HashMap::new();
            headers.insert("Version", "GnuPG v1");
            assert_eq!(key, ArmorBlock::PublicKey{
                headers: headers,
                version: 4,
            })
        } else {
            panic!("failed to parse: {:?}", res);
        }
    }
}
