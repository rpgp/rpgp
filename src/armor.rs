use nom::{self, digit, line_ending, not_line_ending};
use nom::types::CompleteStr;
use crc24;
use base64;
use byteorder::{ByteOrder, BigEndian};
use std::collections::HashMap;
use std::str;

use packet::types::Packet;
use util::{base64_token, end_of_line};
use errors::{Result, Error};

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
    // gnupgp extension
    File,
}


named!(armor_header_sep(&str) -> &str,  tag!("-----"));

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
    ) |
    map!(
        tag!("PGP ARMORED FILE"),
        |_| BlockType::File
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
named!(kv_pair(CompleteStr) -> (CompleteStr, CompleteStr), do_parse!(
    k: take_until!(": ") >>
       tag!(": ")        >>
    v: terminated!(not_line_ending, end_of_line)  >>
    (k, v)
));


/// Armor Headers
fn armor_headers(input: &str) -> nom::IResult<&str, HashMap<String, String>> {
    match map!(CompleteStr(input), many0!(kv_pair), |v| {
        v.iter().map(|p| (p.0.to_string(), p.1.to_string())).collect()
    }) {
        Ok((rem, res)) => Ok((&rem, res)),
        Err(_) => Err(nom::Err::Error(
            error_position!(input, nom::ErrorKind::Many0),
        )),
    }
}

/// Armor Header
named!(armor_header(&str) -> (BlockType, HashMap<String, String>), do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers     >>
    (typ, headers)
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

named!(parse_inner(&str) -> ((BlockType, HashMap<String, String>), Vec<Vec<u8>>, Option<&str>, BlockType), do_parse!(
               take_until!("-----")
    >>   head: armor_header
    >>         many0!(line_ending)
    >>   inner: separated_list_complete!(
                   line_ending, map_res!(base64_token, |v| base64::decode_config(v, base64::MIME))
               )
    >>         many0!(tag!("="))
    >>         opt!(line_ending)
    >>  check: opt!(preceded!(tag!("="), take!(4)))
    >>         many0!(line_ending)
    >> footer: armor_footer_line
    >> (head, inner, check, footer)
));


pub fn parse(mut input: impl ::std::io::Read) -> Result<(BlockType, HashMap<String, String>, Vec<u8>)> {
    // TODO: actual streaming
    let mut input_str = String::new();
    input.read_to_string(&mut input_str)?;
    
    let (_, res) = parse_inner(&input_str)?;
    let (head, inner, check, footer) = res;
    
    let (typ, headers) = head;

    if typ != footer {
        return Err(Error::InvalidArmorWrappers);
    }
    
    let decoded = inner.concat();
    
    if let Some(c) = check {
        let check_new = crc24::hash_raw(decoded.as_slice());
        let check_dec = read_checksum(c.as_bytes());

        if check_new != check_dec {
            return Err(Error::InvalidChecksum);
        }
    }

    Ok((typ, headers, decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
        map.insert("Version".to_string(), "12".to_string());
        map.insert("special-stuff".to_string(), "cool12.0".to_string());
        map.insert("some:colon".to_string(), "with:me".to_string());

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
        map.insert("Version".to_string(), "1.0".to_string());
        map.insert("Mode".to_string(), "Test".to_string());

        assert_eq!(
            armor_header(
                "-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test\n",
            ).unwrap(),
            ("", (BlockType::Message, map))
        );

        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        assert_eq!(
            armor_header(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n",
            ).unwrap(),
            ("", (BlockType::PublicKey, map))
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

    #[test]
    fn test_parse_armor_small() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
Version: GnuPG v1\n\
\n\
mQGiBEig\n\
-----END PGP PUBLIC KEY BLOCK-----\n");
        let (typ, headers, _) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
    }

    #[test]
    fn test_parse_armor_full() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        
        let c = Cursor::new("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\n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\n=XyBX\n-----END PGP PUBLIC KEY BLOCK-----\n");
        let (typ, headers, decoded) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(decoded.len(), 1675);
        assert_eq!(decoded.len() %3, 1); // two padding chars
    }
}
