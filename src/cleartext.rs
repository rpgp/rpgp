//! Implements Cleartext Signature Framework

use std::io::{BufRead, Read};

use buffer_redux::BufReader;

use nom::bytes::streaming::{tag, take_until1};
use nom::character::streaming::{alphanumeric1, line_ending, space0};
use nom::combinator::{complete, map_res};
use nom::multi::many0;
use nom::sequence::{pair, terminated};
use nom::IResult;

use crate::armor::Headers;
use crate::errors::Result;
use crate::types::PublicKeyTrait;
use crate::{Deserializable, StandaloneSignature};

/// Implementation of a Cleartext Signed Message.
///
/// Ref https://datatracker.ietf.org/doc/html/rfc4880.html#section-7
#[derive(Debug)]
pub struct CleartextSignedMessage {
    /// The original text.
    text: String,
    /// The actual signature.
    signature: StandaloneSignature,
    /// Headers for the signature part.
    headers: Headers,
}

impl CleartextSignedMessage {
    /// The signature on the message.
    pub fn signature(&self) -> &StandaloneSignature {
        &self.signature
    }

    /// Verify the signature against the normalized cleartext.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        self.signature
            .verify(key, self.normalized_text().as_bytes())
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

    /// Headers on the signature.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Parse from an arbitrary reader, containing the text of the message.
    pub fn from_bytes<R: Read>(bytes: R) -> Result<Self> {
        Self::from_bytes_buf(BufReader::new(bytes))
    }

    /// Parse from string, containing the text of the message.
    pub fn from_string(input: &str) -> Result<Self> {
        Self::from_bytes_buf(input.as_bytes())
    }

    /// Parse from a buffered reader, containing the text of the message.
    pub fn from_bytes_buf<R: BufRead>(mut b: R) -> Result<Self> {
        debug!("parsing cleartext message");
        // Header line
        read_from_buf(&mut b, armor_header_line)?;

        // Headers (only Hash is allowed)
        let headers_cleartext = read_from_buf(&mut b, armor_headers_lines)?;

        debug!("Found Hash headers: {:?}", headers_cleartext);

        // Cleartext Body
        let text = read_from_buf(&mut b, cleartext_body)?;

        // Signature
        let (signature, headers) = StandaloneSignature::from_armor_single_buf(b)?;

        Ok(Self {
            text,
            signature,
            headers,
        })
    }
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

/// Parses a single armor header line.
fn armor_header_line(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = tag("-----BEGIN PGP SIGNED MESSAGE-----")(i)?;
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
    let (i, lines) = map_res(take_until1("\n-----"), to_string)(i)?;
    let (i, _) = line_ending(i)?;

    Ok((i, lines))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use crate::{types::SecretKeyTrait, SignedSecretKey};

    use super::*;

    #[test]
    fn test_cleartext_openpgp_1() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-1-key-1.asc").unwrap();

        let msg = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(msg.text(), "You are scrupulously honest, frank, and straightforward.  Therefore you\nhave few friends.");
        assert_eq!(msg.headers.len(), 1);
        assert_eq!(
            msg.headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );
    }

    #[test]
    fn test_cleartext_openpgp_2() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-2-keys-1.asc").unwrap();

        let msg = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            msg.text(),
            "\"The geeks shall inherit the earth.\"
		-- Karl Lehenbauer"
        );
        assert_eq!(msg.headers.len(), 1);
        assert_eq!(
            msg.headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );
    }

    #[test]
    fn test_cleartext_openpgp_3() {
        let _ = pretty_env_logger::try_init();

        let data =
            std::fs::read_to_string("./tests/openpgp/samplemsgs/clearsig-2-keys-2.asc").unwrap();

        let msg = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            msg.text(),
            "The very remembrance of my former misfortune proves a new one to me.
		-- Miguel de Cervantes"
        );
        assert_eq!(msg.headers.len(), 1);
        assert_eq!(
            msg.headers.get("Version").unwrap(),
            &vec!["GnuPG v2".to_string()]
        );
    }

    #[test]
    fn test_cleartext_interop_testsuite_1() {
        let _ = pretty_env_logger::try_init();

        let data = std::fs::read_to_string("./tests/unit-tests/cleartext-msg-01.asc").unwrap();

        let msg = CleartextSignedMessage::from_string(&data).unwrap();

        assert_eq!(
            msg.text(),
            "- From the grocery store we need:

- - tofu
- - vegetables
- - noodles

"
        );
        assert!(msg.headers.is_empty());

        assert_eq!(
            msg.normalized_text(),
            "From the grocery store we need:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n\r\n"
        );

        let key_data = std::fs::read_to_string("./tests/unit-tests/cleartext-key-01.asc").unwrap();
        let (key, _) = SignedSecretKey::from_string(&key_data).unwrap();

        msg.verify(&key.public_key()).unwrap();
    }

    #[test]
    fn test_cleartext_body() {
        assert_eq!(
            cleartext_body(b"-- hello\n--world\n-----bla").unwrap(),
            (&b"-----bla"[..], "-- hello\n--world".to_string())
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
}
