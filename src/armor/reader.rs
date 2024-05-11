use std::collections::BTreeMap;
use std::hash::Hasher;
use std::io::prelude::*;
use std::{fmt, io, str};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use buffer_redux::BufReader;
use byteorder::{BigEndian, ByteOrder};

use nom::branch::alt;
use nom::bytes::streaming::{tag, take_until1};
use nom::bytes::streaming::{take, take_until};
use nom::character::streaming::{alphanumeric1, digit1, line_ending, not_line_ending, space0};
use nom::combinator::{complete, map, map_res, opt, success, value};
use nom::multi::many0;
use nom::sequence::{delimited, pair, preceded, terminated};
use nom::IResult;

use crate::base64_decoder::Base64Decoder;
use crate::base64_reader::Base64Reader;
use crate::errors::Result;
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
    /// Cleartext Framework message
    CleartextMessage,
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
            BlockType::CleartextMessage => "PGP SIGNED MESSAGE".into(),
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

/// Armor Headers.
pub type Headers = BTreeMap<String, Vec<String>>;

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
        value(BlockType::CleartextMessage, tag("PGP SIGNED MESSAGE")),
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

/// Parses a single key value pair, for the header.
fn key_value_pair(i: &[u8]) -> IResult<&[u8], (&str, &str)> {
    let (i, key) = map_res(
        alt((
            complete(take_until1(":\r\n")),
            complete(take_until1(":\n")),
            complete(take_until1(": ")),
        )),
        str::from_utf8,
    )(i)?;

    // consume the ":"
    let (i, _) = tag(":")(i)?;
    let (i, t) = alt((tag(" "), line_ending))(i)?;

    let (i, value) = if t == b" " {
        let (i, value) = map_res(not_line_ending, str::from_utf8)(i)?;
        let (i, _) = line_ending(i)?;
        (i, value)
    } else {
        // empty value
        (i, "")
    };

    Ok((i, (key, value)))
}

/// Parses a list of key value pairs.
fn key_value_pairs(i: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
    many0(complete(key_value_pair))(i)
}

/// Parses the full armor header.
fn armor_headers(i: &[u8]) -> IResult<&[u8], Headers> {
    map(key_value_pairs, |pairs| {
        // merge multiple values with the same name
        let mut out = BTreeMap::<String, Vec<String>>::new();
        for (k, v) in pairs {
            let e = out.entry(k.to_string()).or_default();
            e.push(v.to_string());
        }
        out
    })(i)
}

/// Armor Header
fn armor_header(i: &[u8]) -> IResult<&[u8], (BlockType, Headers)> {
    let (i, typ) = armor_header_line(i)?;
    let (i, headers) = match typ {
        BlockType::CleartextMessage => armor_headers_hash(i)?,
        _ => armor_headers(i)?,
    };

    Ok((i, (typ, headers)))
}

fn armor_headers_hash(i: &[u8]) -> IResult<&[u8], Headers> {
    let (i, headers) = many0(complete(hash_header_line))(i)?;
    let (i, _) = pair(space0, line_ending)(i)?;

    let mut res = BTreeMap::new();
    let headers = headers.into_iter().flatten().collect();
    res.insert("Hash".to_string(), headers);

    Ok((i, res))
}

fn hash_header_line(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, _) = tag("Hash: ")(i)?;
    let (i, mut values) = many0(map_res(terminated(alphanumeric1, tag(",")), |s| {
        str::from_utf8(s).map(|s| s.to_string())
    }))(i)?;

    let (i, last_value) = terminated(
        map_res(alphanumeric1, |s| str::from_utf8(s).map(|s| s.to_string())),
        line_ending,
    )(i)?;
    values.push(last_value);

    Ok((i, values))
}

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> std::io::Result<u64> {
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

pub fn header_parser(i: &[u8]) -> IResult<&[u8], (BlockType, Headers, bool)> {
    let (i, prefix) = take_until("-----")(i)?;
    let has_leading_data = !prefix.is_empty();
    let (i, (typ, headers)) = armor_header(i)?;
    let (i, _) = many0(pair(space0, line_ending))(i)?;

    Ok((i, (typ, headers, has_leading_data)))
}

fn footer_parser(i: &[u8]) -> IResult<&[u8], (Option<u64>, BlockType)> {
    let (i, checksum) = map_res(
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
        |c| c.map(read_checksum).transpose(),
    )(i)?;
    let (i, typ) = armor_footer_line(i)?;

    Ok((i, (checksum, typ)))
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
pub struct Dearmor<R: BufRead> {
    /// The ascii armor parsed block type.
    pub typ: Option<BlockType>,
    /// The headers found in the armored file.
    pub headers: Headers,
    /// Optional crc checksum
    pub checksum: Option<u64>,
    /// current state
    current_part: Part<R>,
    crc: crc24::Crc24Hasher,
}

/// Internal indicator, where in the parsing phase we are
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Part<R: BufRead> {
    Header(R),
    Body(Base64Decoder<Base64Reader<R>>),
    Footer(BufReader<R>),
    Done(BufReader<R>),
    Temp,
}

impl<R: BufRead> Dearmor<R> {
    pub fn new(input: R) -> Self {
        Dearmor {
            typ: None,
            headers: BTreeMap::new(),
            checksum: None,
            current_part: Part::Header(input),
            crc: Default::default(),
        }
    }

    pub fn into_parts(self) -> (Option<BlockType>, Headers, Option<u64>, BufReader<R>) {
        let Self {
            typ,
            headers,
            checksum,
            current_part,
            ..
        } = self;
        let Part::Done(b) = current_part else {
            panic!("can only be called when done");
        };

        (typ, headers, checksum, b)
    }

    pub fn read_only_header(mut self) -> Result<(BlockType, Headers, bool, R)> {
        let header = std::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, leading) = Self::read_header_internal(&mut b)?;
            return Ok((typ, headers, leading, b));
        }

        bail!("invalid state, cannot read header");
    }

    pub fn after_header(typ: BlockType, headers: Headers, input: R) -> Self {
        Self {
            typ: Some(typ),
            headers,
            checksum: None,
            current_part: Part::Body(Base64Decoder::new(Base64Reader::new(input))),
            crc: Default::default(),
        }
    }

    pub fn read_header(&mut self) -> Result<()> {
        let header = std::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, _has_leading_data) = Self::read_header_internal(&mut b)?;
            self.typ = Some(typ);
            self.headers = headers;
            self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
            return Ok(());
        }

        bail!("invalid state, cannot read header");
    }

    fn read_header_internal(b: &mut R) -> Result<(BlockType, Headers, bool)> {
        let (typ, headers, leading) = read_from_buf(b, "armor header", header_parser)?;
        Ok((typ, headers, leading))
    }

    fn read_body(
        &mut self,
        into: &mut [u8],
        base_decoder: &mut Base64Decoder<Base64Reader<R>>,
    ) -> io::Result<usize> {
        let size = base_decoder.read(into)?;
        if size > 0 {
            // update the hash
            self.crc.write(&into[0..size]);
        }

        Ok(size)
    }

    fn read_footer(&mut self, mut b: BufReader<R>) -> Result<()> {
        let (checksum, footer_typ) = read_from_buf(&mut b, "armor footer", footer_parser)?;
        if let Some(ref header_typ) = self.typ {
            if header_typ != &footer_typ {
                self.current_part = Part::Done(b);
                bail!(
                    "armor ascii footer does not match header: {:?} != {:?}",
                    self.typ,
                    footer_typ
                );
            }
        }
        self.checksum = checksum;
        self.current_part = Part::Done(b);

        // check checksum if there is one
        if let Some(expected) = self.checksum {
            let actual = self.crc.finish();
            if expected != actual {
                bail!("invalid crc24 checksum");
            }
        }

        Ok(())
    }
}

impl<R: BufRead> Read for Dearmor<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        loop {
            let current_part = std::mem::replace(&mut self.current_part, Part::Temp);
            match current_part {
                Part::Header(mut b) => {
                    let (typ, headers, _leading) = Self::read_header_internal(&mut b)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    self.typ = Some(typ);
                    self.headers = headers;
                    self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
                }
                Part::Body(mut b) => {
                    let last_read = self.read_body(&mut into[read..], &mut b)?;
                    if last_read == 0 && read < into.len() {
                        // we are done with the body
                        let (b, buf) = b.into_inner_with_buffer();
                        let b = BufReader::with_buffer(buf, b.into_inner());
                        self.current_part = Part::Footer(b);
                    } else {
                        self.current_part = Part::Body(b);
                    }
                    read += last_read;
                    if read == into.len() {
                        return Ok(read);
                    }
                }
                Part::Footer(mut b) => {
                    b.make_room();
                    while b.buf_len() < 128 {
                        let read = b.read_into_buf()?;
                        if read == 0 {
                            break;
                        }
                    }

                    self.read_footer(b)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                Part::Done(b) => {
                    self.current_part = Part::Done(b);
                    return Ok(read);
                }
                Part::Temp => panic!("invalid state"),
            }
        }
    }
}

pub(crate) fn read_from_buf<B: BufRead, T, P: Fn(&[u8]) -> IResult<&[u8], T>>(
    b: &mut B,
    ctx: &str,
    parser: P,
) -> Result<T> {
    let mut last_was_incomplete = false;
    loop {
        let buf = b.fill_buf()?;
        if buf.is_empty() {
            bail!("not enough bytes in buffer: {}", ctx);
        }
        match parser(buf) {
            Ok((remaining, res)) => {
                let consumed = buf.len() - remaining.len();
                b.consume(consumed);
                return Ok(res);
            }
            Err(nom::Err::Incomplete(_)) => {
                if last_was_incomplete {
                    bail!("failed reading: {}: not enough bytes", ctx);
                }
                last_was_incomplete = true;
                continue;
            }
            Err(err) => {
                bail!("failed reading: {} {:?}", ctx, err);
            }
        };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // helper function to parse all data at once
    pub fn parse(input: &str) -> Result<(BlockType, Headers, Vec<u8>)> {
        let mut dearmor = Dearmor::new(BufReader::new(input.as_bytes()));

        // estimate size
        let mut bytes = Vec::new();
        dearmor.read_to_end(&mut bytes)?;

        Ok((dearmor.typ.unwrap(), dearmor.headers, bytes))
    }

    // helper function to parse all data at once
    pub fn parse_raw(input: &str) -> Result<(BlockType, Headers, Vec<u8>)> {
        let mut dearmor = Dearmor::new(input.as_bytes());

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
        map.insert("Version".to_string(), vec!["12".to_string()]);
        map.insert("special-stuff".to_string(), vec!["cool12.0".to_string()]);
        map.insert("some:colon".to_string(), vec!["with:me".to_string()]);

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
        map.insert("Version".to_string(), vec!["1.0".to_string()]);
        map.insert("Mode".to_string(), vec!["Test".to_string()]);

        assert_eq!(
            armor_header(&b"-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test\n"[..],).unwrap(),
            (&b""[..], (BlockType::Message, map))
        );

        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), vec!["GnuPG v1".to_string()]);

        assert_eq!(
            armor_header(&b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n"[..],)
                .unwrap(),
            (&b""[..], (BlockType::PublicKey, map))
        );
    }

    #[test]
    fn test_parse_armor_small() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), vec!["GnuPG v1".to_string()]);

        let c = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n";

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_missing_header_value() {
        let mut map = BTreeMap::new();
        map.insert("NoVal".to_string(), vec!["".to_string()]);

        let c = "\
             -----BEGIN PGP MESSAGE-----\n\
             NoVal:\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\
             ";

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_whitespace() {
        let c = "\
             -----BEGIN PGP MESSAGE-----\n\
             \t \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\
             ";

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert!(headers.is_empty());
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_two_entries() {
        let mut map = BTreeMap::new();
        map.insert("hello".to_string(), vec!["world".to_string()]);

        let c = "\
             -----BEGIN PGP MESSAGE-----\n\
             hello: world\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\n\
             -----BEGIN PGP MESSAGE-----\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP MESSAGE-----\
             ";

        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::Message));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_full() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), vec!["GnuPG v1".to_string()]);

        let c = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
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
             -----END PGP PUBLIC KEY BLOCK-----\n";
        let (typ, headers, decoded) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(decoded.len(), 1675);
        assert_eq!(decoded.len() % 3, 1); // two padding chars
    }

    #[test]
    fn test_parse_armor_full_no_header() {
        let c = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----\n";
        let (typ, _, _) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PrivateKeyPKCS1(PKCS1Type::RSA)));
    }

    #[test]
    fn test_dearmor_small_stream() {
        let mut map = BTreeMap::new();
        map.insert("Version".to_string(), vec!["GnuPG v1".to_string()]);

        let c = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n";

        let mut dec = Dearmor::new(BufReader::new(c.as_bytes()));

        let mut res = vec![0u8; 5];
        let read = dec.read(&mut res).unwrap();

        // first read reads the header
        assert_eq!(dec.typ, Some(BlockType::PublicKey));
        assert_eq!(dec.headers, map);

        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"hello"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b" worl"[..]); // codespell:ignore worl

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 1);
        assert_eq!(res.as_slice()[0], b'd');

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 0);
        assert_eq!(res.as_slice()[0], b'd'); // unchanged
    }

    #[test]
    fn test_key_value_pair_single() {
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
            key_value_pair(&b"hello:\r\n"[..]).unwrap(),
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
    fn test_key_value_pairs_single() {
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
    fn test_key_value_pairs_multiple() {
        assert_eq!(
            key_value_pairs(&b"hello: world\nhello: stuff\n"[..]).unwrap(),
            (&b""[..], vec![("hello", "world"), ("hello", "stuff")]),
            "single"
        );
    }

    #[test]
    fn test_footer_parser() {
        assert!(footer_parser(b"-----END PGP MESSAGE----").is_err());
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
            Ok((&b""[..], (Some(14717027), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"=4JBj\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"),
            Ok((&b""[..], (Some(14717027), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(b"\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"),
            Ok((&b""[..], (None, BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(&b"=XyBX\n-----END PGP PUBLIC KEY BLOCK-----\n"[..]),
            Ok((&b""[..], (Some(6234199), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(&b"-----END PGP MESSAGE-----\n-----BEGIN PGP MESSAGE-----\n\naGVsbG8gd29ybGQ=\n-----END PGP MESSAGE-----\n"[..]),
            Ok((
                &b"-----BEGIN PGP MESSAGE-----\n\naGVsbG8gd29ybGQ=\n-----END PGP MESSAGE-----\n"[..],
                (None, BlockType::Message)
            )),
        );
    }

    #[test]
    fn test_hash_header_line() {
        assert_eq!(
            hash_header_line(b"Hash: hello,world\n").unwrap(),
            (&[][..], vec!["hello".to_string(), "world".to_string()]),
        );

        assert_eq!(
            hash_header_line(b"Hash: hello\n").unwrap(),
            (&[][..], vec!["hello".to_string()]),
        );

        assert_eq!(
            hash_header_line(b"Hash: hello\n\n").unwrap(),
            (&b"\n"[..], vec!["hello".to_string()]),
        );
    }

    #[test]
    fn test_armor_headers_lines() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Hash".to_string(),
            vec!["hello".to_string(), "world".to_string()],
        );

        assert_eq!(
            armor_headers_hash(b"Hash: hello,world\n\n").unwrap(),
            (&[][..], headers),
        );

        let mut headers = BTreeMap::new();
        headers.insert(
            "Hash".to_string(),
            vec!["hello".to_string(), "world".to_string(), "cool".to_string()],
        );

        assert_eq!(
            armor_headers_hash(b"Hash: hello,world\nHash: cool\n\n").unwrap(),
            (&[][..], headers,),
        );
    }

    #[test]
    fn test_regression_long_key_1() {
        let _ = pretty_env_logger::try_init();
        let input = std::fs::read_to_string("./tests/unit-tests/long-key.asc").unwrap();
        let (typ, headers, decoded) = parse(&input).unwrap();

        assert_eq!(typ, BlockType::PublicKey);
        assert!(headers.is_empty());
        let expected_binary_s: String =
            std::fs::read_to_string("./tests/unit-tests/long-key.asc.line")
                .unwrap()
                .lines()
                .collect();
        let expected_binary = base64::engine::general_purpose::STANDARD
            .decode(expected_binary_s)
            .unwrap();
        assert_eq!(hex::encode(expected_binary), hex::encode(decoded));
    }

    #[test]
    fn test_regression_long_key_2_1() {
        let _ = pretty_env_logger::try_init();
        let input = std::fs::read_to_string("./tests/unit-tests/long-key-2.asc").unwrap();
        let (typ, headers, decoded) = parse(&input).unwrap();

        assert_eq!(typ, BlockType::PublicKey);
        assert!(headers.is_empty());
        let expected_binary_s: String =
            std::fs::read_to_string("./tests/unit-tests/long-key-2.asc.line")
                .unwrap()
                .lines()
                .collect();
        let expected_binary = base64::engine::general_purpose::STANDARD
            .decode(expected_binary_s)
            .unwrap();
        assert_eq!(hex::encode(expected_binary), hex::encode(decoded));
    }

    #[test]
    fn test_regression_long_key_2_2() {
        let _ = pretty_env_logger::try_init();
        let input = std::fs::read_to_string("./tests/unit-tests/long-key-2.asc").unwrap();
        let (typ, headers, decoded) = parse_raw(&input).unwrap();

        assert_eq!(typ, BlockType::PublicKey);
        assert!(headers.is_empty());
        let expected_binary_s: String =
            std::fs::read_to_string("./tests/unit-tests/long-key-2.asc.line")
                .unwrap()
                .lines()
                .collect();
        let expected_binary = base64::engine::general_purpose::STANDARD
            .decode(expected_binary_s)
            .unwrap();
        assert_eq!(hex::encode(expected_binary), hex::encode(decoded));
    }
}
