use std::collections::BTreeMap;
use std::hash::Hasher;
use std::io::prelude::*;
use std::{fmt, io, str};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use buffer_redux::BufReader;
use byteorder::{BigEndian, ByteOrder};

use nom::branch::alt;
use nom::bytes::streaming::tag;
use nom::bytes::streaming::{take, take_until};
use nom::character::streaming::{digit1, line_ending, not_line_ending, space0};
use nom::combinator::{complete, map, map_res, opt, success, value};
use nom::multi::many0;
use nom::sequence::{delimited, pair, preceded, terminated};
use nom::{IResult, InputIter, InputLength, Slice};

use crate::base64_decoder::Base64Decoder;
use crate::base64_reader::Base64Reader;
use crate::errors::Result;
use crate::line_reader::LineReader;
use crate::ser::Serialize;

/// Armor block types.
///
/// Both OpenPGP (RFC4880) and OpenSSL PEM armor types are included.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum BlockType {
    /// PGP public key
    PublicKey,
    /// PEM encoded PKCS#1 public key
    PublicKeyPKCS1(PKCS1Type),
    /// PEM encoded PKCS#8 public key
    PublicKeyPKCS8,
    /// Public key OpenSSH
    PublicKeyOpenssh,
    /// PGP private key
    PrivateKey,
    /// PEM encoded PKCS#1 private key
    PrivateKeyPKCS1(PKCS1Type),
    /// PEM encoded PKCS#8 private key
    PrivateKeyPKCS8,
    /// OpenSSH private key
    PrivateKeyOpenssh,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
    // gnupgp extension
    File,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Serialize for BlockType {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(self.as_string().as_bytes())?;

        Ok(())
    }
}

impl BlockType {
    fn as_string(&self) -> String {
        match self {
            BlockType::PublicKey => "PGP PUBLIC KEY BLOCK".into(),
            BlockType::PrivateKey => "PGP PRIVATE KEY BLOCK".into(),
            BlockType::MultiPartMessage(x, y) => format!("PGP MESSAGE, PART {x}/{y}"),
            BlockType::Message => "PGP MESSAGE".into(),
            BlockType::Signature => "PGP SIGNATURE".into(),
            BlockType::File => "PGP ARMORED FILE".into(),
            BlockType::PublicKeyPKCS1(typ) => format!("{typ} PUBLIC KEY"),
            BlockType::PublicKeyPKCS8 => "PUBLIC KEY".into(),
            BlockType::PublicKeyOpenssh => "OPENSSH PUBLIC KEY".into(),
            BlockType::PrivateKeyPKCS1(typ) => format!("{typ} PRIVATE KEY"),
            BlockType::PrivateKeyPKCS8 => "PRIVATE KEY".into(),
            BlockType::PrivateKeyOpenssh => "OPENSSH PRIVATE KEY".into(),
        }
    }
}

/// OpenSSL PKCS#1 PEM armor types
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PKCS1Type {
    RSA,
    DSA,
    EC,
}

impl fmt::Display for PKCS1Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PKCS1Type::RSA => write!(f, "RSA"),
            PKCS1Type::DSA => write!(f, "DSA"),
            PKCS1Type::EC => write!(f, "EC"),
        }
    }
}

/// Parses a single ascii armor header separator.
fn armor_header_sep(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"-----")(i)
}

#[inline]
fn parse_digit(x: &[u8]) -> Result<usize> {
    let s = str::from_utf8(x)?;
    let digit: usize = s.parse()?;
    Ok(digit)
}

/// Parses the type inside of an ascii armor header.
fn armor_header_type(i: &[u8]) -> IResult<&[u8], BlockType> {
    alt((
        value(BlockType::PublicKey, tag("PGP PUBLIC KEY BLOCK")),
        value(BlockType::PrivateKey, tag("PGP PRIVATE KEY BLOCK")),
        map(
            preceded(
                tag("PGP MESSAGE, PART "),
                pair(
                    map_res(digit1, parse_digit),
                    opt(preceded(tag("/"), map_res(digit1, parse_digit))),
                ),
            ),
            |(x, y)| BlockType::MultiPartMessage(x, y.unwrap_or(0)),
        ),
        value(BlockType::Message, tag("PGP MESSAGE")),
        value(BlockType::Signature, tag("PGP SIGNATURE")),
        value(BlockType::File, tag("PGP ARMORED FILE")),
        // OpenSSL formats

        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PUBLIC KEY"),
        ),
        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PUBLIC KEY"),
        ),
        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::EC),
            tag("EC PUBLIC KEY"),
        ),
        // Public Key File PKCS#8
        value(BlockType::PublicKeyPKCS8, tag("PUBLIC KEY")),
        // OpenSSH Public Key File
        value(BlockType::PublicKeyOpenssh, tag("OPENSSH PUBLIC KEY")),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PRIVATE KEY"),
        ),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PRIVATE KEY"),
        ),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::EC),
            tag("EC PRIVATE KEY"),
        ),
        // Private Key File PKCS#8
        value(BlockType::PrivateKeyPKCS8, tag("PRIVATE KEY")),
        // OpenSSH Private Key File
        value(BlockType::PrivateKeyOpenssh, tag("OPENSSH PRIVATE KEY")),
    ))(i)
}

/// Parses a single armor header line.
fn armor_header_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    delimited(
        pair(armor_header_sep, tag(b"BEGIN ")),
        armor_header_type,
        pair(armor_header_sep, line_ending),
    )(i)
}

/// Recognizes one or more key tokens.
fn key_token(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let input_length = input.input_len();

    for (idx, item) in input.iter_indices() {
        // are we done? ": " is reached
        let is_colon_space =
            item == b':' && idx + 1 < input_length && input.slice(idx + 1..idx + 2)[0] == b' ';
        if is_colon_space {
            return Ok((input.slice(idx + 2..), input.slice(0..idx)));
        }

        // ":\n" reached
        let is_colon_line_ending = item == b':'
            && idx + 1 < input_length
            && (input.slice(idx + 1..idx + 2)[0] == b'\n'
                || input.slice(idx + 1..idx + 2)[0] == b'\r');
        if is_colon_line_ending {
            return Ok((input.slice(idx + 1..), input.slice(0..idx)));
        }
    }

    Ok((input.slice(input_length..), input))
}

/// Parses a single key value pair, for the header.
fn key_value_pair(i: &[u8]) -> IResult<&[u8], (&str, &str)> {
    terminated(
        pair(
            map_res(key_token, str::from_utf8),
            map_res(opt(not_line_ending), |r| {
                str::from_utf8(r.unwrap_or(b"".as_slice()))
            }),
        ),
        line_ending,
    )(i)
}

/// Parses a list of key value pairs.
fn key_value_pairs(i: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
    many0(complete(key_value_pair))(i)
}

/// Parses the full armor header.
fn armor_headers(i: &[u8]) -> IResult<&[u8], BTreeMap<String, String>> {
    map(key_value_pairs, |pairs| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    })(i)
}

/// Armor Header
fn armor_header(i: &[u8]) -> IResult<&[u8], (BlockType, BTreeMap<String, String>)> {
    pair(armor_header_line, armor_headers)(i)
}

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> ::std::io::Result<u64> {
    let checksum = STANDARD
        .decode(input)
        .map_err(|_| io::ErrorKind::InvalidData)?;

    let mut buf = [0; 4];
    let mut i = checksum.len();
    for a in checksum.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }

    Ok(u64::from(BigEndian::read_u32(&buf)))
}

fn header_parser(i: &[u8]) -> IResult<&[u8], (BlockType, BTreeMap<String, String>)> {
    delimited(
        take_until(b"-----".as_slice()),
        armor_header,
        many0(pair(space0, line_ending)),
    )(i)
}

fn footer_parser(i: &[u8]) -> IResult<&[u8], (Option<&[u8]>, BlockType)> {
    pair(
        alt((
            delimited(
                tag(b"="),
                map(take(4u8), Some),
                pair(many0(line_ending), tag(b"--")),
            ),
            delimited(
                many0(tag(b"=")),
                success(None),
                pair(many0(line_ending), tag(b"--")),
            ),
        )),
        armor_footer_line,
    )(i)
}

/// Parses a single armor footer line
fn armor_footer_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    // Only 3, because we parsed two already in the `footer_parser`.
    delimited(
        tag(b"---END "),
        armor_header_type,
        pair(armor_header_sep, opt(complete(line_ending))),
    )(i)
}

/// Streaming based ascii armor parsing.
pub struct Dearmor<R> {
    /// The ascii armor parsed block type.
    pub typ: Option<BlockType>,
    /// The headers found in the armored file.
    pub headers: BTreeMap<String, String>,
    /// Optional crc checksum
    pub checksum: Option<u64>,
    /// track what we are currently parsing
    current_part: Part,
    /// the underlying data source, wrapped in a BufferedReader
    inner: Option<BufReader<R>>,
    /// base64 decoder
    base_decoder: Option<
        Base64Decoder<base64::engine::GeneralPurpose, Base64Reader<LineReader<BufReader<R>>>>,
    >,
    /// Are we done?
    done: bool,
    crc: crc24::Crc24Hasher,
}

/// Internal indicator, where in the parsing phase we are
#[derive(Debug, PartialEq, Eq)]
enum Part {
    Header,
    Body,
    Footer,
}

const CAPACITY: usize = 1024 * 32;

impl<R: Read + Seek> Dearmor<R> {
    pub fn new(input: R) -> Self {
        Dearmor {
            typ: None,
            headers: BTreeMap::new(),
            checksum: None,
            current_part: Part::Header,
            base_decoder: None,
            inner: Some(BufReader::with_capacity(CAPACITY, input)),
            done: false,
            crc: Default::default(),
        }
    }

    pub fn read_header(&mut self) -> io::Result<()> {
        if let Some(ref mut b) = self.inner {
            b.read_into_buf()?;

            // no data available currently
            if b.buf_len() == 0 {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "empty buffer"));
            }

            let consumed = match header_parser(b.buffer()) {
                Ok((remaining, (typ, header))) => {
                    self.typ = Some(typ);
                    self.headers = header;
                    self.current_part = Part::Body;

                    b.buf_len() - remaining.len()
                }
                Err(nom::Err::Incomplete(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "incomplete parse",
                    ));
                }
                Err(err) => {
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid ascii armor header: {err:?}"),
                    ));
                }
            };

            b.consume(consumed);
        } else {
            panic!("invalid state");
        }

        Ok(())
    }

    fn read_body(&mut self, into: &mut [u8]) -> io::Result<usize> {
        if self.base_decoder.is_none() {
            let b = self.inner.take().ok_or_else(|| {
                self.done = true;
                io::Error::new(io::ErrorKind::UnexpectedEof, "bad parser state")
            })?;
            self.base_decoder = Some(Base64Decoder::new(Base64Reader::new(LineReader::new(b))));
        }

        // "allow" as workaround for https://github.com/rust-lang/rust-clippy/issues/12208
        #[allow(clippy::unused_io_amount)]
        let size = if let Some(ref mut base_decoder) = self.base_decoder {
            base_decoder.read(into)?
        } else {
            unreachable!();
        };

        if size == 0 && !into.is_empty() {
            // we are done with the body
            self.current_part = Part::Footer;
            self.read_footer()
        } else if size == 0 {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing footer",
            ))
        } else {
            // update the hash
            self.crc.write(&into[0..size]);

            Ok(size)
        }
    }

    fn read_footer(&mut self) -> io::Result<usize> {
        if self.base_decoder.is_some() {
            let decoder = self
                .base_decoder
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "bad parser state"))?;
            let (base_reader, buffer_outer) = decoder.into_inner_with_buffer();

            let line_reader: LineReader<_> = base_reader.into_inner();
            let mut b = BufReader::with_buffer(buffer_outer, line_reader.into_inner());
            b.make_room();

            b.read_into_buf()?;
            if b.buf_len() == 0 {
                // we are done here
                return Ok(0);
            }

            let consumed = match footer_parser(b.buffer()) {
                Ok((remaining, (checksum, footer_typ))) => {
                    if let Some(ref header_typ) = self.typ {
                        if header_typ != &footer_typ {
                            self.done = true;
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "armor ascii footer does not match header: {:?} != {:?}",
                                    self.typ, footer_typ
                                ),
                            ));
                        }
                    }

                    if let Some(raw) = checksum {
                        self.checksum = Some(read_checksum(raw)?);
                    }

                    b.buf_len() - remaining.len()
                }
                Err(nom::Err::Incomplete(_)) => {
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "incomplete parse",
                    ));
                }
                Err(err) => {
                    warn!(
                        "invalid ascii armor footer: `{:?}`",
                        ::std::str::from_utf8(b.buffer())
                    );
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid ascii armor footer: {err:?}"),
                    ));
                }
            };

            b.consume(consumed);
            self.done = true;

            // check checksum if there is one
            if let Some(expected) = self.checksum {
                let actual = self.crc.finish();

                if expected != actual {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid crc24 checksum",
                    ));
                }
            }
        } else {
            panic!("invalid state");
        }

        // We always return zero, as we do not write to the `into` buffer.
        Ok(0)
    }
}

impl<R: Read + Seek> Read for Dearmor<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }

        match self.current_part {
            Part::Header => {
                self.read_header()?;
                self.read_body(into)
            }
            Part::Body => self.read_body(into),
            Part::Footer => self.read_footer(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Cursor;

    use crate::errors::Result;

    // helper function to parse all data at once
    pub fn parse<R: Read + Seek>(
        mut input: R,
    ) -> Result<(BlockType, BTreeMap<String, String>, Vec<u8>)> {
        let mut dearmor = Dearmor::new(input.by_ref());

        // estimate size
        let mut bytes = Vec::new();
        dearmor.read_to_end(&mut bytes)?;

        Ok((dearmor.typ.unwrap(), dearmor.headers, bytes))
    }

    #[test]
    fn test_armor_header_line() {
        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE-----\n"[..]).unwrap(),
            (&b""[..], BlockType::Message)
        );

        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 3/14-----\n"[..]).unwrap(),
            (&b""[..], BlockType::MultiPartMessage(3, 14))
        );

        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 14-----\n"[..]).unwrap(),
            (&b""[..], BlockType::MultiPartMessage(14, 0))
        );
    }

    #[test]
    fn test_armor_headers() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "12".to_string());
        map.insert("special-stuff".to_string(), "cool12.0".to_string());
        map.insert("some:colon".to_string(), "with:me".to_string());

        assert_eq!(
            armor_headers(
                &b"Version: 12\r\nspecial-stuff: cool12.0\r\nsome:colon: with:me\r\n"[..],
            )
            .unwrap(),
            (&b""[..], map)
        );
    }

    #[test]
    fn test_armor_header() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "1.0".to_string());
        map.insert("Mode".to_string(), "Test".to_string());

        assert_eq!(
            armor_header(&b"-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test\n"[..],).unwrap(),
            (&b""[..], (BlockType::Message, map))
        );

        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        assert_eq!(
            armor_header(&b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n"[..],)
                .unwrap(),
            (&b""[..], (BlockType::PublicKey, map))
        );
    }

    #[test]
    fn test_parse_armor_small() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );
        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_missing_header_value() {
        let mut map = BTreeMap::new();
        map.insert("NoVal".to_string(), "".to_string());

        let c = Cursor::new(
            "\
             -----BEGIN PGP MESSAGE-----\n\
             NoVal:\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE----\
             ",
        );

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_whitespace() {
        let c = Cursor::new(
            "\
             -----BEGIN PGP MESSAGE-----\n\
             \t \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE----\
             ",
        );

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert!(headers.is_empty());
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_two_entries() {
        let mut map = BTreeMap::new();
        map.insert("hello".to_string(), "world".to_string());

        let c = Cursor::new(
            "\
             -----BEGIN PGP MESSAGE-----\n\
             hello: world\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\n\
             -----BEGIN PGP MESSAGE-----\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\
             ",
        );

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_full() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             mQGiBEigu7MRBAD7gZJzevtYLB3c1pE7uMwu+zHzGGJDrEyEaz0lYTAaJ2YXmJ1+\n\
             IvmvBI/iMrRqpFLR35uUcz2UHgJtIP+xenCF4WIhHv5wg3XvBvTgG/ooZaj1gtez\n\
             miXV2bXTlEMxSqsZKvkieQRrMv3eV2VYhgaPvp8xJhl+xs8eVhlrmMv94wCgzWUw\n\
             BrOICLPF5lANocvkqGNO3UUEAMH7GguhvXNlIUncqOpHC0N4FGPirPh/6nYxa9iZ\n\
             kQEEg6mB6wPkaHZ5ddpagzFC6AncoOrhX5HPin9T6+cPhdIIQMogJOqDZ4xsAYCY\n\
             KwjkoLQjfMdS5CYrMihFm4guNMKpWPfCe/T4TU7tFmTug8nnAIPFh2BNm8/EqHpg\n\
             jR4JA/9wJMxv+2eFuFGeLtiPjo+o2+AfIxTTEIlWyNkO+a9KkzmPY/JP4OyVGKjM\n\
             V+aO0vZ6FamdlrXAaAPm1ULmY5pC15P/hNr0YAbN28Y8cwNGuuKGbiYvYD35KKhs\n\
             5c5/pfMy0rgDElhFTGd4rpZdkHei3lwF5cyV0htv5s2lwGJKnrQnQW5kcm9pZCBT\n\
             ZWN1cml0eSA8c2VjdXJpdHlAYW5kcm9pZC5jb20+iGAEExECACAFAkigu7MCGwMG\n\
             CwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRBzHmufAFQPw547AKDIDW3mDx+84xk1\n\
             EfzH/uNQQLYBBgCeMabHPlx+2+IGnfPsQ8UsxMPLFnO5BA0ESKC72BAQALKb8W8l\n\
             U3Xs+lbquuVEA5x+mNnJriRnq1q1ZA8J43z0lCqT6n+q/nICuE/SjGxfp+8G/K3/\n\
             LrIfBWLLQHZMQyk/1Eild/ZoRxNAbjTGiQY6HWrZOd+Z2fWiSN03nSSpWImPbua3\n\
             6LwSRRZNmZ77tdY0hI9TqJzqax1WQWk7IxfWubNTbNsPiktm/d6C2P04OkKOAmr8\n\
             QCqKLLCO578zYLTgraL6F4g2YVurGgAB1KFSX2F8fh6Igr+pIW/ytoS9n2H+uecR\n\
             l+2RB6Pq7MahwZvPPeMavwUMPQpOI6Or3pYZTzp/IJWNyL6MOBzV5q4gkD0xYtEq\n\
             Ihr1hX1IdiGdOA4oH1Rk1K/XIPwLelQdYp3ftiReh4/Gb3kfKCxpmMXL1f/ndx6N\n\
             zIiqweDU5mZBpXBsBzFZfUDALL4VGqpc2eEltkVtD0RuQI2YaImBjOPsHI4StN5t\n\
             2OspWke4xJGf0PqRVjTDJmtUrIJX4X5Fh8M85unHYYIpBCaDbM/7/xIaNQbQfdeO\n\
             6yqGrj/0WAjL34wbo4D12BiPeoUTreD60aNwmpu5z1NRPS2Wn+6kTIHGhf47wGTZ\n\
             v9OFYWhgSs3INpna4VA4E8SpOWPd8LFYLs9clAlaUhqJyLJ3JlmXmhGnWM41z+p9\n\
             RA8UQXhvQcvYJSR77SC4O503wdVKJ07OH6WbAAMFD/4yjBZ+X7QBIKTLHXAIQBjB\n\
             526iOhmfxyIgmX4vWcggJFZrBxPFulkGJj65Mwr9AwZeIceukKQUGcf2LpEoIdZY\n\
             dP8gEshRDZQ1Y3GDD9ukChRDoK9kFIxnYmH8euU/TwTPtAEEDASfwEZnM5DcJQOA\n\
             Q6G3GVKr/8uwmT5hUn5sR2L9vmrjw1nPkfZeDQNBmeTI8A+byosp6Nxl8thJIGNt\n\
             8UTa02+g/nbf+ODRrEf3xeeFUNb14kTqULNT/hTj8/6xDwxwaF2ms60kYxA/EXDB\n\
             21jqmhnfUwjSa++R38Qig9tGwOo83Z7uNCqtU3caFW1P55iD/Sju/ZecHVSgfq6j\n\
             2H7mNWfvB9ILkS7w1w/InjEA7LpY9jtmPKDIYYQ7YGZuxFwOxtw69ulkS6ddc1Pt\n\
             AQ5oe0d59rBicE8R7rBCxwzMihG5ctJ+a+t4/MHqi6jy/WI9OK+SwWmCeT1nVy6F\n\
             NZ00QOPe89DFBCqhj4qSGfjOtCEKAM7SOhkyEYJ8jk5KrsLOcWPOM9i3uus1RquG\n\
             XJ2Cljt6zJYtEnpkjrw+Ge0SBDNEMGZEBLbEZKECtNJ2NBrMRKYeAseCGNQ+uJOz\n\
             8vL7ztUKoi1SbFGuHkv5N2NmPq42QrN8dftW01DceGDnJ1KHRvCUbpPcyQYFhRFb\n\
             nxd3tMIEGO83iEmozvJfB4hJBBgRAgAJBQJIoLvYAhsMAAoJEHMea58AVA/D6ewA\n\
             ninKQSW+oL4z28F3T0GHag38WeWyAJ45d7dx4z0GxhTm2b9DclLombY+nw==\n\
             =XyBX\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );
        let (typ, headers, decoded) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(decoded.len(), 1675);
        assert_eq!(decoded.len() % 3, 1); // two padding chars
    }

    #[test]
    fn test_parse_armor_full_no_header() {
        let c = Cursor::new(
            "-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxp4sIUtrNBl4Vbd4075CmtHmwxTc0FhQIGw36kptbrWReLb9
Np0RQylKyc6qUruxZlCdPVFo7iX3vs272/0GEakPv0DAsKGbe1nTsMyxxz0o3dP4
JQOlOGEnpETa0ybfPLMX1+qNiBdm7HLjqcP5+S0Exb0Z0deFNIhEP6XckUEgHmwA
/AdDdUUKwwvZeZOi4XyBVt0vXzwM/+84ro27O+CZm9Du3qe1jTIsX7jUrqsUBhp9
eUwa1jXfXuJJo9b4/GeP4S9x8U7ho+BQ6/HH03dzcKaY3FftanCZkcwxfGBBUiCK
pIA5WgKimLcgP2R75Y3jilDoBh5HyIdGXo0aFwIDAQABAoIBAQCBXLIHeXS4eUJc
KeSjnQ8KgV4Yf3UWqf5+L533lkRSUCYQhrbDpGeC49kXOejLe/4eUrEnJ+f8/HOx
LZSGwvT5+bAM9CLMqGV5YNc1Fw1PZHFCkfXUPdyVrQnBvyr7Th0mDsuf0OAf3IYn
yOipQMCGX6D1HaY8e3AB+CLjhab0X1vAwvqzPb/HIdtMhRWlJxzbuqnE3kr+Ccvz
us3vmD4VBp0CF0f+yblcibMCHdHY6j8Ir6Qeq6Mbd6lEXRPW1TgUqP15idVaJ4AF
1kGXDW9O0ycgrbopGZfk5yY60fEHGdr4QYjx2Gtx2xQcnPcjJ+j5kGgubKWxNhJE
Qx7DPdYxAoGBAP29S+wD1df0U+Tr0x06N6M/nSjNacGs12Oq/ehNJHhTYUO9fWUl
M2X/MXRMMMGsnGaLNsrLao9Jnq0ZU5GFICWYeVBvaCvRrGngbqJBy8jRv+QYyaQs
AckLcdgLGvjhcXonHDcbcxpug7/qFwakT+KY2s11FrHBEzbAIuDiSSKfAoGBAMhj
KPkrjWJh3xxpFrFnGYj5aF86ExrPe2LAP/8F6Ez7dQN+4bA6O5F4hpJ/X0q/6s0n
IBljo/DgARCBjbwDSaAMEWdm8HDeBhJsSCdQHW38ylaRDi8CQDKR60N3a/tV1MRJ
4fKoHZ+7HH3wc+Bjv3oDovwVyUMG7ekCjeqbqI2JAoGBAOkhYX5Jz9KJBAPSwLeb
4760FfuFL+PooEVMt9kV96ouQbFxiqLB2UWfgJqv3iQ0Kcb1pbQRzag1Jfs4x9Vu
ESk5vEyw729DSDxHHp8qAMhUHxC9zZZvcHx9bW3oVjHRQOfQw1XGfK0OWTKdK+bI
VTWG55HaQK21DahCREmG31dVAoGBALBH80KHmsAioziGBi2YKjGCXtvu5eGfBsdP
orzBQKOATmb91qLGB6MoaRI1NOo4POGu+qD7M7xyAt23aq0sIzfFhgX1260e1C6e
zTawVsNsL7/JqbWXAEy8az+VrguTbTIkYL2sQStEWoM75WRPu6El09p5e+0YCnEC
C0CJINUpAoGBAPF1fpPINHlUW+Bvo4Nj3935QgZI47yTplDusptyfYgFYXw6ZYel
y5Zgv9TWZlmW9FDTp4XVgn5zQTEN1LdL7vNXWV9aOvfrqPk5ClBkxhndgq7j6MFs
9+9V06HJDIsSrC0D/ajIkP+iT9Hd6eEZMkJ6y6XtTbkJGYt2zOtnrpb6
-----END RSA PRIVATE KEY-----\n",
        );
        let (typ, _, _) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PrivateKeyPKCS1(PKCS1Type::RSA)));
    }

    #[test]
    fn test_dearmor_small_stream() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );

        let mut dec = Dearmor::new(c);

        let mut res = vec![0u8; 5];
        let read = dec.read(&mut res).unwrap();

        // first read reads the header
        assert_eq!(dec.typ, Some(BlockType::PublicKey));
        assert_eq!(dec.headers, map);

        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"hello"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b" worl"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 1);
        assert_eq!(res.as_slice()[0], b'd');

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 0);
        assert_eq!(res.as_slice()[0], b'd'); // unchanged
    }

    #[test]
    fn test_key_value_pair() {
        assert_eq!(
            key_value_pair(&b"hello: world\n"[..]).unwrap(),
            (&b""[..], ("hello", "world")),
            "single"
        );

        assert_eq!(
            key_value_pair(&b"hello:\n"[..]).unwrap(),
            (&b""[..], ("hello", "")),
            "empty"
        );

        assert_eq!(
            key_value_pair(&b"hello: world\nother content"[..]).unwrap(),
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
            key_value_pairs(&b"hello:\ncool: stuff\n"[..]).unwrap(),
            (&b""[..], vec![("hello", ""), ("cool", "stuff")]),
            "empty"
        );

        assert_eq!(
            key_value_pairs(&b"hello: world\ncool: stuff\nother content"[..]).unwrap(),
            (
                &b"other content"[..],
                vec![("hello", "world"), ("cool", "stuff")]
            ),
            "with rest"
        );
    }

    #[test]
    fn test_footer_parser() {
        assert_eq!(
            footer_parser(b"-----END PGP PUBLIC KEY BLOCK-----"),
            Ok((&b""[..], (None, BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"-----END PGP PUBLIC KEY BLOCK-----\n"),
            Ok((&b""[..], (None, BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"=-----END PGP PUBLIC KEY BLOCK-----\n"),
            Ok((&b""[..], (None, BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"=4JBj-----END PGP PUBLIC KEY BLOCK-----\r\n"),
            Ok((&b""[..], (Some(&b"4JBj"[..]), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"=4JBj\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"),
            Ok((&b""[..], (Some(&b"4JBj"[..]), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"),
            Ok((&b""[..], (None, BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(&b"=XyBX\n-----END PGP PUBLIC KEY BLOCK-----\n"[..]),
            Ok((&b""[..], (Some(&b"XyBX"[..]), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(&b"-----END PGP MESSAGE-----\n-----BEGIN PGP MESSAGE-----\n\naGVsbG8gd29ybGQ=\n-----END PGP MESSAGE-----\n"[..]),
            Ok((
                &b"-----BEGIN PGP MESSAGE-----\n\naGVsbG8gd29ybGQ=\n-----END PGP MESSAGE-----\n"[..],
                (None, BlockType::Message)
            )),
        );
    }
}
