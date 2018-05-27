use nom::{self, digit, line_ending, not_line_ending};
use nom::types::CompleteStr;
use crc24;
use base64;
use byteorder::{ByteOrder, BigEndian};
use std::collections::HashMap;
use std::str;

use packet::Packet;
use util::{base64_token, end_of_line};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Block<'a> {
    pub typ: BlockType,
    pub headers: HashMap<&'a str, &'a str>,
    pub packets: Vec<Packet>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockType {
    PublicKey,
    PrivateKey,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
}

named!(armor_header_sep(&str) -> &str, tag!("-----"));

named!(armor_header_type(&str) -> BlockType, alt_complete!(
    map!(
        tag!("PGP PUBLIC KEY BLOCK"),
        |_| BlockType::PublicKey
    ) |
    map!(
        tag!("PGP PRIVATE KEY BLOCK"),
        |_| BlockType::PrivateKey
    ) |
    do_parse!(
           tag!("PGP MESSAGE, PART ") >>
        x: digit >>
        y: opt!(preceded!(tag!("/"), digit)) >>
        ({
            // unwraps are safe, as the parser already determined that this is a digit.
            
            let x: usize = x.parse().unwrap();
            let y: usize = y.map(|s| s.parse().unwrap()).unwrap_or(0);
            
            BlockType::MultiPartMessage(x, y)
        })    
    ) |
    map!(
        tag!("PGP MESSAGE"),
        |_| BlockType::Message
    ) |
    map!(
        tag!("PGP SIGNATURE"),
        |_| BlockType::Signature
    )
));

named!(
    armor_header_line(&str) -> BlockType,
    do_parse!(
         armor_header_sep  >>
         tag!("BEGIN ")    >>
    typ: armor_header_type >>
         armor_header_sep  >>
         line_ending       >>
    (typ)
)
);

named!(armor_footer_line(&str) -> BlockType, do_parse!(
         armor_header_sep  >>
         tag!("END ")      >>
    typ: armor_header_type >>
         armor_header_sep  >>
         alt_complete!(line_ending | eof!()) >>
    (typ)
)
);

/// Armor Header Key-Value Pair
named!(kv_pair(CompleteStr) -> (CompleteStr, CompleteStr), dbg_dmp!(do_parse!(
    k: take_until!(": ") >>
       tag!(": ")        >>
    v: terminated!(not_line_ending, end_of_line)  >>
    ((k, v))
)));


/// Armor Headers
pub fn armor_headers(input: &str) -> nom::IResult<&str, HashMap<&str, &str>> {
    match map!(CompleteStr(input), many0!(kv_pair), |v| {
        v.iter().map(|p| (*p.0, *p.1)).collect()
    }) {
        Ok((rem, res)) => Ok((&rem, res)),
        Err(_) => Err(nom::Err::Error(
            error_position!(input, nom::ErrorKind::Many0),
        )),
    }
}
pub fn armor_headers_c(input: CompleteStr) -> nom::IResult<CompleteStr, HashMap<&str, &str>> {
    map!(
        input,
        many0!(kv_pair),
        |v: Vec<(CompleteStr, CompleteStr)>| v.iter().map(|p| (*p.0, *p.1)).collect()
    )
}

/// Armor Header
named!(armor_header(&str) -> (BlockType, HashMap<&str, &str>), do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers     >>
    ((typ, headers))
));

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> u32 {
    let raw = base64::decode_config(input, base64::MIME).expect("Invalid base64 encoding checksum");
    let mut buf = [0; 4];
    let mut i = raw.len();
    for a in raw.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }

    BigEndian::read_u32(&buf)
}

named!(pub parse(&str) -> (BlockType, HashMap<&str, &str>, Vec<u8>), do_parse!(
         head: armor_header
    >>         many0!(line_ending)
    >>   inner: map!(separated_list_complete!(
                   line_ending, base64_token
               ), |v| v.join("")) 
    >>    pad: map!(many0!(tag!("=")), |v| v.join(""))
    >>         opt!(line_ending)
    >>  check: opt!(preceded!(tag!("="), take!(4)))
    >>         many1!(line_ending)
    >> footer: armor_footer_line
    >> ({
        let (typ, headers) = head;
        
        // println!("{:?}", inner);
        
        // TODO: proper error handling
        assert_eq!(typ, footer, "Non matching armor wrappers");

        // TODO: proper error handling
        let decoded = base64::decode_config(&(inner + &pad), base64::MIME).expect("Invalid base64 encoding");

        if let Some(c) = check {
            let check_new = crc24::hash_raw(decoded.as_slice());
            let check_dec = read_checksum(c.as_bytes());
            
            // TODO: proper error handling
            assert_eq!(check_new, check_dec, "Corrupted data, checksum missmatch");
        }
        
        (typ, headers, decoded)
    })
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_header_line() {
        assert_eq!(
            armor_header_line("-----BEGIN PGP MESSAGE-----\n").unwrap(),
            ("", BlockType::Message)
        );

        assert_eq!(armor_header_line("-----BEGIN PGP MESSAGE, PART 3/14-----\n").unwrap(), ("", BlockType::MultiPartMessage(3, 14)));

        assert_eq!(armor_header_line("-----BEGIN PGP MESSAGE, PART 14-----\n").unwrap(), ("", BlockType::MultiPartMessage(14, 0)));
    }

    #[test]
    fn test_armor_headers() {
        let mut map = HashMap::new();
        map.insert("Version", "12");
        map.insert("special-stuff", "cool12.0");
        map.insert("some:colon", "with:me");

        assert_eq!(
            armor_headers(
                "Version: 12\r\nspecial-stuff: cool12.0\r\nsome:colon: with:me",
            ).unwrap(),
            ("", map)
        );
    }

    #[test]
    fn test_armor_header() {
        let mut map = HashMap::new();
        map.insert("Version", "1.0");
        map.insert("Mode", "Test");

        assert_eq!(
            armor_header(
                "-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test\n",
            ).unwrap(),
            ("", (BlockType::Message, map))
        );
    }

    #[test]
    fn test_kv_pair() {
        assert_eq!(kv_pair(CompleteStr("hel-lo: world")).unwrap(), (
            CompleteStr(
                "",
            ),
            (
                CompleteStr(
                    "hel-lo",
                ),
                CompleteStr(
                    "world",
                ),
            ),
        ));
    }
}
