//! Implements Cleartext Signature Framework

use std::collections::HashSet;
use std::io::{BufRead, Read};

use buffer_redux::BufReader;

use chrono::SubsecRound;
use nom::branch::alt;
use nom::bytes::streaming::{tag, take_until1};
use nom::character::streaming::{alphanumeric1, line_ending, space0};
use nom::combinator::{complete, map_res};
use nom::multi::many0;
use nom::sequence::{pair, terminated};
use nom::IResult;
use smallvec::SmallVec;

use crate::armor::{self, Headers};
use crate::crypto::hash::HashAlgorithm;
use crate::errors::Result;
use crate::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use crate::types::{KeyVersion, PublicKeyTrait, SecretKeyTrait};
use crate::{ArmorOptions, Deserializable, Signature, StandaloneSignature};

/// Implementation of a Cleartext Signed Message.
///
/// Ref https://datatracker.ietf.org/doc/html/rfc4880.html#section-7
#[derive(Debug)]
pub struct CleartextSignedMessage {
    /// The original text.
    text: String,
    /// Preferred hashes
    hashes: Vec<HashAlgorithm>,
    /// The actual signature.
    signatures: Vec<StandaloneSignature>,
}

impl CleartextSignedMessage {
    /// Construct a new cleartext message and signs it using the given key.
    pub fn new<F>(
        text: &str,
        config: SignatureConfig,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> String,
    {
        let hash = config.hash_alg;
        let escaped_text = dash_escape(text.as_bytes())?;
        let signature = config.sign(key, key_pw, text.as_bytes())?;
        let signature = StandaloneSignature::new(signature);

        Ok(Self {
            text: escaped_text,
            hashes: vec![hash],
            signatures: vec![signature],
        })
    }

    /// Sign the given text.
    pub fn sign<F>(text: &str, key: &impl SecretKeyTrait, key_pw: F) -> Result<Self>
    where
        F: FnOnce() -> String,
    {
        let key_id = key.key_id();
        let algorithm = key.algorithm();
        let hash_algorithm = key.hash_alg();
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                SmallVec::from_slice(&key.fingerprint()),
            )),
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            )),
        ];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key_id))];

        let config = SignatureConfig::new_v4(
            Default::default(),
            SignatureType::Text,
            algorithm,
            hash_algorithm,
            hashed_subpackets,
            unhashed_subpackets,
        );

        Self::new(text, config, key, key_pw)
    }

    /// Sign the same message with multiple keys.
    ///
    /// The signer function gets invoked with the original text to be signed,
    /// and needs to produce the individual signatures.
    pub fn new_many<F>(text: &str, signer: F) -> Result<Self>
    where
        F: FnOnce(&str) -> Result<Vec<Signature>>,
    {
        let escaped_text = dash_escape(text.as_bytes())?;
        let raw_signatures = signer(text)?;
        let mut hashes = HashSet::new();
        let mut signatures = Vec::new();

        for signature in raw_signatures {
            hashes.insert(signature.hash_alg());
            let signature = StandaloneSignature::new(signature);
            signatures.push(signature);
        }

        Ok(Self {
            text: escaped_text,
            hashes: hashes.into_iter().collect(),
            signatures,
        })
    }

    /// The signature on the message.
    pub fn signatures(&self) -> &[StandaloneSignature] {
        &self.signatures
    }

    /// Verify the signature against the normalized cleartext.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        let nt = self.normalized_text();
        for signature in &self.signatures {
            signature.verify(key, nt.as_bytes())?;
        }
        Ok(())
    }

    /// Verify each signature, potentially agains a different key.
    pub fn verify_many<F>(&self, verifier: F) -> Result<()>
    where
        F: Fn(usize, &StandaloneSignature, &[u8]) -> Result<()>,
    {
        let nt = self.normalized_text();
        for (i, signature) in self.signatures.iter().enumerate() {
            verifier(i, signature, nt.as_bytes())?;
        }
        Ok(())
    }

    /// Normalizes the text to the format it is used as signature.
    pub fn normalized_text(&self) -> String {
        let mut out = String::new();
        for line in self.text.lines() {
            // drop dash escapes if they exist
            if let Some(line) = line.strip_prefix("- ") {
                out += line;
            } else {
                out += line;
            }
            out += "\r\n";
        }

        out
    }

    /// The clear text of the message.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Parse from an arbitrary reader, containing the text of the message.
    pub fn from_bytes<R: Read>(bytes: R) -> Result<(Self, Headers)> {
        Self::from_bytes_buf(BufReader::new(bytes))
    }

    /// Parse from string, containing the text of the message.
    pub fn from_string(input: &str) -> Result<(Self, Headers)> {
        Self::from_bytes_buf(input.as_bytes())
    }

    /// Parse from a buffered reader, containing the text of the message.
    pub fn from_bytes_buf<R: BufRead>(mut b: R) -> Result<(Self, Headers)> {
        debug!("parsing cleartext message");
        // Header line
        read_from_buf(&mut b, armor_header_line)?;

        // Headers (only Hash is allowed)
        let hash_headers = read_from_buf(&mut b, armor_headers_lines)?;
        let hashes = hash_headers
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_>>()?;

        debug!("Found Hash headers: {:?}", hashes);

        // Cleartext Body
        let text = read_from_buf(&mut b, cleartext_body)?;

        // Signature
        let (signatures, headers) = StandaloneSignature::from_armor_many_buf(b)?;
        let signatures = signatures.collect::<Result<_>>()?;

        Ok((
            Self {
                text,
                hashes,
                signatures,
            },
            headers,
        ))
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        // Header
        writer.write_all(HEADER_LINE.as_bytes())?;
        writer.write_all(&[b'\n'])?;

        // Hashes
        for hash in &self.hashes {
            writer.write_all(b"Hash: ")?;
            writer.write_all(hash.to_string().as_bytes())?;
            writer.write_all(&[b'\n'])?;
        }
        writer.write_all(&[b'\n'])?;

        // Cleartext body
        writer.write_all(self.text.as_bytes())?;
        writer.write_all(&[b'\n'])?;

        armor::write(
            &self.signatures,
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )?;

        Ok(())
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, opts)?;
        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }
}

/// Dash escape the given text.
///
/// Ref https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-dash-escaped-text
fn dash_escape<R: BufRead>(text: R) -> Result<String> {
    let mut out = String::new();
    for line in text.lines() {
        let line = line?;
        if line.starts_with('-') {
            out += "- ";
        }
        out.push_str(&line);
        out += "\n";
    }
    Ok(out)
}

fn read_from_buf<B: BufRead, T, P: Fn(&[u8]) -> IResult<&[u8], T>>(
    b: &mut B,
    parser: P,
) -> Result<T> {
    loop {
        let buf = b.fill_buf()?;
        if buf.is_empty() {
            bail!("not enough bytes in buffer");
        }

        match parser(buf) {
            Ok((remaining, res)) => {
                let consumed = buf.len() - remaining.len();
                b.consume(consumed);
                return Ok(res);
            }
            Err(nom::Err::Incomplete(_)) => {
                continue;
            }
            Err(err) => {
                bail!("failed reading: {:?}", err);
            }
        };
    }
}

const HEADER_LINE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

/// Parses a single armor header line.
fn armor_header_line(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = tag(HEADER_LINE)(i)?;
    let (i, _) = line_ending(i)?;

    Ok((i, ()))
}

fn armor_headers_lines(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, headers) = many0(complete(hash_header_line))(i)?;
    let (i, _) = pair(space0, line_ending)(i)?;

    Ok((i, headers.into_iter().flatten().collect()))
}

fn hash_header_line(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, _) = tag("Hash: ")(i)?;
    let (i, mut values) = many0(map_res(terminated(alphanumeric1, tag(",")), to_string))(i)?;

    let (i, last_value) = terminated(map_res(alphanumeric1, to_string), line_ending)(i)?;
    values.push(last_value);

    Ok((i, values))
}

fn to_string(b: &[u8]) -> std::result::Result<String, std::str::Utf8Error> {
    std::str::from_utf8(b).map(|s| s.to_string())
}

fn cleartext_body(i: &[u8]) -> IResult<&[u8], String> {
    let (i, lines) = map_res(
        alt((
            complete(take_until1("\r\n-----")),
            complete(take_until1("\n-----")),
        )),
        to_string,
    )(i)?;
    let (i, _) = line_ending(i)?;

    Ok((i, lines))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use crate::SignedSecretKey;

    use super::*;

    #[test]
    fn test_cleartext_openpgp_1() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-1-key-1.asc").unwrap();

        let (msg, headers) = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(normalize(msg.text()), normalize("You are scrupulously honest, frank, and straightforward.  Therefore you\nhave few friends."));
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );

        assert_eq!(msg.signatures().len(), 1);

        roundtrip(&data, &msg, &headers);
    }

    #[test]
    fn test_cleartext_openpgp_2() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-2-keys-1.asc").unwrap();

        let (msg, headers) = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            normalize(msg.text()),
            normalize("\"The geeks shall inherit the earth.\"\n		-- Karl Lehenbauer")
        );
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );

        assert_eq!(msg.signatures().len(), 2);

        roundtrip(&data, &msg, &headers);
    }

    #[test]
    fn test_cleartext_openpgp_3() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-2-keys-2.asc").unwrap();

        let (msg, headers) = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            normalize(msg.text()),
            normalize("The very remembrance of my former misfortune proves a new one to me.\n		-- Miguel de Cervantes")
        );
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );

        roundtrip(&data, &msg, &headers);
    }

    #[test]
    fn test_cleartext_interop_testsuite_1() {
        let _ = pretty_env_logger::try_init();

        let data = std::fs::read_to_string("./tests/unit-tests/cleartext-msg-01.asc").unwrap();

        let (msg, headers) = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            normalize(msg.text()),
            normalize(
                "- From the grocery store we need:\n\n- - tofu\n- - vegetables\n- - noodles\n\n"
            )
        );
        assert!(headers.is_empty());

        assert_eq!(
            msg.normalized_text(),
            "From the grocery store we need:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n\r\n"
        );

        let key_data = std::fs::read_to_string("./tests/unit-tests/cleartext-key-01.asc").unwrap();
        let (key, _) = SignedSecretKey::from_string(&key_data).unwrap();

        msg.verify(&key.public_key()).unwrap();
        assert_eq!(msg.signatures().len(), 1);

        roundtrip(&data, &msg, &headers);
    }

    fn roundtrip(expected: &str, msg: &CleartextSignedMessage, headers: &Headers) {
        let expected = normalize(expected);
        let out = msg.to_armored_string(Some(headers).into()).unwrap();
        let out = normalize(out);

        assert_eq!(expected, out);
    }

    fn normalize(a: impl AsRef<str>) -> String {
        a.as_ref().replace("\r\n", "\n").replace('\r', "\n")
    }

    #[test]
    fn test_cleartext_body() {
        assert_eq!(
            cleartext_body(b"-- hello\n--world\n-----bla").unwrap(),
            (&b"-----bla"[..], "-- hello\n--world".to_string())
        );

        assert_eq!(
            cleartext_body(b"-- hello\r\n--world\r\n-----bla").unwrap(),
            (&b"-----bla"[..], "-- hello\r\n--world".to_string())
        );
    }

    #[test]
    fn test_armor_headers_lines() {
        assert_eq!(
            armor_headers_lines(b"Hash: hello,world\n\n").unwrap(),
            (&[][..], vec!["hello".to_string(), "world".to_string()]),
        );
        assert_eq!(
            armor_headers_lines(b"Hash: hello,world\nHash: cool\n\n").unwrap(),
            (
                &[][..],
                vec!["hello".to_string(), "world".to_string(), "cool".to_string()]
            ),
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
    fn test_dash_escape() {
        let input = "From the grocery store we need:

- tofu
- vegetables
- noodles

";
        let expected = "From the grocery store we need:

- - tofu
- - vegetables
- - noodles

";

        assert_eq!(dash_escape(input.as_bytes()).unwrap(), expected);
    }
}
