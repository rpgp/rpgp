use nom::{self, digit, line_ending, not_line_ending, Needed, Offset, eol, is_space, is_alphanumeric, IResult, InputIter,
          InputLength, InputTake, Slice, AsBytes};
use std::ops::{Range, RangeFrom, RangeTo};
use std::hash::Hasher;

use nom::types::CompleteStr;
use crc24;
use base64;
use byteorder::{ByteOrder, BigEndian};
use std::collections::HashMap;
use std::str;
use circular::Buffer;

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
named!(armor_header_sep_b,  tag!("-----"));

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
named!(armor_header_type_b<BlockType>, alt_complete!(
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
            let x: usize = ::std::str::from_utf8(x).unwrap().parse().unwrap();
            let y: usize = y.map(|s| ::std::str::from_utf8(s).unwrap().parse().unwrap()).unwrap_or(0);
            
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

named!(
    armor_header_line_b<BlockType>,
    do_parse!(
         armor_header_sep_b  >>
         tag!("BEGIN ")    >>
    typ: armor_header_type_b >>
         armor_header_sep_b  >>
         line_ending       >>
    ({println!("got header: {:?}", typ); typ})
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
named!(armor_footer_line_b<BlockType>, do_parse!(
         armor_header_sep_b  >>
         tag!("END ")      >>
    typ: armor_header_type_b >>
         armor_header_sep_b  >>
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

named!(key_value_sep, tag!(": "));

/// Recognizes one or more key tokens.
pub fn key_token(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let input_length = input.input_len();

    for (idx, item) in input.iter_indices() {
        if item == b':' {
            // are we done? ": " is reached
            if input.slice(idx+1..idx+2)[0] == b' ' {
                return Ok((input.slice(idx+2..), input.slice(0..idx)))
            }
        }
    }
    
    Ok((input.slice(input_length..), input))
}

named!(key_value<(&str, &str)>, do_parse!(
         key: map_res!(key_token, ::std::str::from_utf8)
    >> value: map_res!(terminated!(not_line_ending, line_ending), ::std::str::from_utf8)
    >> (key, value)
));

named!(key_value_pairs<Vec<(&str, &str)>>, many0!(complete!(key_value)));


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


/// Armor Headers
named!(armor_headers_b<HashMap<String, String>>, do_parse!(
    pairs: key_value_pairs
    >> (pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
));

/// Armor Header
named!(armor_header(&str) -> (BlockType, HashMap<String, String>), do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers    >>
    (typ, headers)
));

/// Armor Header
named!(armor_header_b(&[u8]) -> (BlockType, HashMap<String, String>), do_parse!(
    typ:     armor_header_line_b >>
    headers: armor_headers_b     >>
    (typ, headers)
));

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> u64 {
    let raw = base64::decode_config(input, base64::MIME).expect("Invalid base64 encoding checksum");
    let mut buf = [0; 4];
    let mut i = raw.len();
    for a in raw.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }

    BigEndian::read_u32(&buf) as u64
}


named!(header_parser(&[u8]) -> (BlockType, HashMap<String, String>), do_parse!(
               take_until!("-----")
    >>   head: armor_header_b
    >>         many0!(line_ending)
    >> (head.0, head.1)
));

named!(body_parser<&[u8]>, alt!(base64_token | line_ending));

named!(footer_parser<(Option<&[u8]>, BlockType)>, do_parse!(
               // possible padding chars from base64
               many0!(tag!("="))
    >>         opt!(line_ending)
    >>    crc: opt!(preceded!(tag!("="), take!(4)))
    >>         many0!(line_ending)
    >> footer: armor_footer_line_b
    >> (crc, footer)
));

pub struct Dearmor<R> {
    pub typ: Option<BlockType>,
    pub headers: HashMap<String, String>,

    // track what we are currently parsing
    current_part: Part,
    buffer: Buffer,
    inner: R,
    capacity: usize,
    crc: crc24::Crc24Hasher,
}

#[derive(Debug)]
enum Part {
    Header,
    Body,
    Footer,
}

impl<R: ::std::io::Read> Dearmor<R> {
    pub fn new(input: R) -> Dearmor<R> {
        Dearmor {
            typ: None,
            headers: HashMap::new(),
            current_part: Part::Header,
            buffer: Buffer::with_capacity(32 * 1024),
            capacity: 32 * 1024,
            inner: input,
            crc: crc24::Crc24Hasher::new(),
        }
    }
}



impl<R: ::std::io::Read> ::std::io::Read for Dearmor<R> {
    fn read(&mut self, into: &mut [u8]) -> ::std::io::Result<usize> {
        // TODO: const/configurable
        let max_capacity = 1024 * 1024 * 1024;
        // how much data have we read into our target `into`
        let mut read = 0;
        // how much data did we consume from our inner source
        let mut consumed = 0;
        // how much data do we want to read
        let into_len = into.len();
        
        while read < into_len {
            let b = &mut self.buffer;
            let sz = self.inner.read(b.space())?;
            b.fill(sz);

            if b.available_data() == 0 {
                break;
            }

            let mut needed: Option<Needed> = None;
            loop {
                println!("parsing: {:?}", b.data());
                let l = match self.current_part {
                    Part::Header => match header_parser(b.data()) {
                        Ok((remaining, (typ, header))) => {
                            println!("parsed header {:?} {:?}", &typ, &header);
                            self.typ = Some(typ);
                            self.headers = header;
                            self.current_part = Part::Body;
                            b.data().offset(remaining)
                        }
                        Err(err) => match err {
                            nom::Err::Incomplete(n) => {
                                needed = Some(n);
                                break;
                            },
                            _ => {
                                println!("nom error: {:?}", err);
                                return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, "header parsing failure"))
                            }
                        }
                    }
                    Part::Body => {
                        println!("body parsing");
                        let data = if into_len > b.data().len() {
                            b.data()
                        } else {
                            &b.data()[0..into_len]
                        };
                        println!("parsing: {:?}", data);
                        match body_parser(data) {
                            Ok((remaining, bytes)) => {
                                println!("parsed body: {:?}", bytes);
                                self.current_part = Part::Body;

                                into[0..bytes.len()].copy_from_slice(bytes);
                                read += bytes.len();
                                self.crc.write(bytes);
                                
                                b.data().offset(remaining)
                            }
                            Err(err) => match err {
                                nom::Err::Incomplete(n) => {
                                    println!("missing: {:?}", n);
                                    needed = Some(n);
                                    break;
                                },
                                nom::Err::Error(e) => {
                                    // this happens when there are no more base64 tokens, so lets move
                                    // to parse the rest
                                    self.current_part = Part::Footer;
                                    0
                                }
                                nom::Err::Failure(err) => {
                                    println!("nom error: {:?}", err);
                                    return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, "body parsing failure"))
                                }
                            }
                        }
                    }
                    Part::Footer => match footer_parser(b.data()) {
                        Ok((remaining, (crc, footer_typ))) => {
                            if let Some(ref header_typ) = self.typ {
                                if header_typ != &footer_typ {
                                    return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, format!("missmatch in armor ascii footer: {:?} != {:?}", self.typ, footer_typ)));
                                }
                            }
                            
                            if let Some(c) = crc {
                                let check_new = self.crc.finish();
                                let check_dec = read_checksum(c.as_bytes());

                                if check_new != check_dec {
                                    return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, "invalid checksum"));
                                }
                            }

                            b.data().offset(remaining)
                        }
                        Err(err) => match err {
                            nom::Err::Incomplete(n) => {
                                needed = Some(n);
                                break;
                            },
                            _ => {
                                println!("nom error: {:?}", err);
                                return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, "footer parsing failure"))
                            }
                        }
                    }                        
                };

                b.consume(l);
                consumed = l;

                // break if we filled the input
                if read == into_len {
                    break;
                }
                
                if let Some(Needed::Size(sz)) = needed {
                    println!("need more data! {}", sz);
                    if sz > b.capacity() && self.capacity * 2 < max_capacity {
                        self.capacity *= 2;
                        b.grow(self.capacity);
                    }
                }
            }
        }

        Ok(read)
    }
}

pub fn parse(mut input: impl ::std::io::Read) -> Result<(BlockType, HashMap<String, String>, Vec<u8>)> {
    // TODO: actual streaming
    let mut input_str = String::new();
    input.read_to_string(&mut input_str)?;
    unimplemented!();
    // // let (_, res) = parse_inner(&input_str)?;
    // // let (head, inner, check, footer) = res;
    
    // let (typ, headers) = head;

    // if typ != footer {
    //     return Err(Error::InvalidArmorWrappers);
    // }
    
    // let decoded = inner.concat();
    
    // if let Some(c) = check {
    //     let check_new = crc24::hash_raw(decoded.as_slice());
    //     let check_dec = read_checksum(c.as_bytes());

    //     if check_new != check_dec {
    //         return Err(Error::InvalidChecksum);
    //     }
    // }

    // Ok((typ, headers, decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

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

    #[test]
    fn test_parse_armor_small_stream() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n");

        let mut dec = Dearmor::new(c);
        
        let mut res = vec![0u8; 5];
        let read = dec.read(&mut res).unwrap();

        // first read reads the header
        assert_eq!(dec.typ, Some(BlockType::PublicKey));
        assert_eq!(dec.headers, map);
        
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"aGVsb"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"G8gd2"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"9ybGQ"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 0);
        assert_eq!(res.as_slice(), &b"9ybGQ"[..]); // unchanged
    }


    #[test]
    fn test_key_value() {
        assert_eq!(
            key_value(&b"hello: world\n"[..]).unwrap(),
            (&b""[..], ("hello", "world")),
            "single"
        );
        
        assert_eq!(
            key_value(&b"hello: world\nother content"[..]).unwrap(),
            (&b"other content"[..], ("hello", "world")),
            "with rest"
        );
    }

    #[test]
    fn test_key_value_pairs() {
        assert_eq!(
            key_value_pairs(&b"hello: world\ncool: stuff\n"[..]).unwrap(),
            (&b""[..], vec![("hello", "world"), ("cool", "stuff")]),
            "single"
        );
        
        assert_eq!(
            key_value_pairs(&b"hello: world\ncool: stuff\nother content"[..]).unwrap(),
            (&b"other content"[..], vec![("hello", "world"), ("cool", "stuff")]),
            "with rest"
        );        
    }
    
    #[test]
    fn test_body_parser() {
        assert_eq!(
            body_parser(&b"abcabc+==\n=hello"[..]),
            Ok((&b"==\n=hello"[..], &b"abcabc+"[..]))
        );
        assert_eq!(
            body_parser(&b"abcabc+==\n-other"[..]),
            Ok((&b"==\n-other"[..], &b"abcabc+"[..]))
        );

        assert_eq!(
            body_parser(&b"ab++\n"[..]),
            Ok((&b"\n"[..], &b"ab++"[..]))
        );

        assert_eq!(
            body_parser(&b"ab"[..]),
            Ok((&b""[..], &b"ab"[..]))
        );
    }
}
