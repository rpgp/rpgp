//! Implements Cleartext Signature Framework

use std::{
    collections::HashSet,
    io::{BufRead, Read},
};

use buffer_redux::BufReader;
use chrono::SubsecRound;
use log::debug;

use crate::{
    armor::{self, header_parser, read_from_buf, BlockType, Headers},
    composed::{ArmorOptions, Deserializable, StandaloneSignature},
    crypto::hash::HashAlgorithm,
    errors::{bail, ensure, ensure_eq, format_err, InvalidInputSnafu, Result},
    line_writer::LineBreak,
    normalize_lines::{normalize_lines, NormalizedReader},
    packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
    MAX_BUFFER_SIZE,
};

/// Implementation of a Cleartext Signed Message.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextSignedMessage {
    /// Normalized and dash-escaped representation of the signed text.
    /// This is exactly the format that gets serialized in cleartext format.
    ///
    /// This representation retains the line-ending encoding of the input material.
    csf_encoded_text: String,

    /// Hash algorithms that are used in the signature(s) in this message
    hashes: Vec<HashAlgorithm>,

    /// The actual signature(s).
    signatures: Vec<StandaloneSignature>,
}

impl CleartextSignedMessage {
    /// Construct a new cleartext message and sign it using the given key.
    pub fn new(
        text: &str,
        config: SignatureConfig,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
    ) -> Result<Self>
where {
        let mut bytes = text.as_bytes();
        let signature_text = NormalizedReader::new(&mut bytes, LineBreak::Crlf);
        let hash = config.hash_alg;
        let signature = config.sign(key, key_pw, signature_text)?;
        let signature = StandaloneSignature::new(signature);

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes: vec![hash],
            signatures: vec![signature],
        })
    }

    /// Sign the given text.
    pub fn sign<R>(
        rng: &mut R,
        text: &str,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
    ) -> Result<Self>
    where
        R: rand::RngCore + rand::CryptoRng + ?Sized,
    {
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
        ];

        let mut config = SignatureConfig::from_key(rng, key, SignatureType::Text)?;
        config.hashed_subpackets = hashed_subpackets;

        // If the version of the issuer is greater than 4, this subpacket MUST NOT be included in
        // the signature.
        if key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];
        }

        Self::new(text, config, key, key_pw)
    }

    /// Sign the same message with multiple keys.
    ///
    /// The signer function gets invoked with the normalized original text to be signed,
    /// and needs to produce the individual signatures.
    pub fn new_many<F>(text: &str, signer: F) -> Result<Self>
    where
        F: FnOnce(&str) -> Result<Vec<Signature>>,
    {
        let signature_text = normalize_lines(text, LineBreak::Crlf);

        let raw_signatures = signer(&signature_text[..])?;
        let mut hashes = HashSet::new();
        let mut signatures = Vec::new();

        for signature in raw_signatures {
            let hash_alg = signature
                .hash_alg()
                .ok_or_else(|| InvalidInputSnafu {}.build())?;
            hashes.insert(hash_alg);
            let signature = StandaloneSignature::new(signature);
            signatures.push(signature);
        }

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes: hashes.into_iter().collect(),
            signatures,
        })
    }

    /// The signature on the message.
    pub fn signatures(&self) -> &[StandaloneSignature] {
        &self.signatures
    }

    /// Verify the signature against the normalized cleartext.
    ///
    /// On success returns the first signature that verified against this key.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<&StandaloneSignature> {
        let nt = self.signed_text();
        for signature in &self.signatures {
            if signature.verify(key, nt.as_bytes()).is_ok() {
                return Ok(signature);
            }
        }

        bail!("No matching signature found")
    }

    /// Verify each signature, potentially against a different key.
    pub fn verify_many<F>(&self, verifier: F) -> Result<()>
    where
        F: Fn(usize, &StandaloneSignature, &[u8]) -> Result<()>,
    {
        let nt = self.signed_text();
        for (i, signature) in self.signatures.iter().enumerate() {
            verifier(i, signature, nt.as_bytes())?;
        }
        Ok(())
    }

    /// Normalizes the text to the format that was hashed for the signature.
    /// The output is normalized to "\r\n" line endings.
    pub fn signed_text(&self) -> String {
        let unescaped = dash_unescape_and_trim(&self.csf_encoded_text);

        normalize_lines(&unescaped, LineBreak::Crlf).to_string()
    }

    /// The "cleartext framework"-encoded (i.e. dash-escaped) form of the message.
    pub fn text(&self) -> &str {
        &self.csf_encoded_text
    }

    /// Parse from an arbitrary reader, containing the text of the message.
    pub fn from_armor<R: Read>(bytes: R) -> Result<(Self, Headers)> {
        Self::from_armor_buf(BufReader::new(bytes), MAX_BUFFER_SIZE)
    }

    /// Parse from string, containing the text of the message.
    pub fn from_string(input: &str) -> Result<(Self, Headers)> {
        Self::from_armor_buf(input.as_bytes(), MAX_BUFFER_SIZE)
    }

    /// Parse from a buffered reader, containing the text of the message.
    pub fn from_armor_buf<R: BufRead>(mut b: R, limit: usize) -> Result<(Self, Headers)> {
        debug!("parsing cleartext message");
        // Headers
        let (typ, headers, has_leading_data) =
            read_from_buf(&mut b, "cleartext header", limit, header_parser)?;
        ensure_eq!(typ, BlockType::CleartextMessage, "unexpected block type");
        ensure!(
            !has_leading_data,
            "must not have leading data for a cleartext message"
        );

        Self::from_armor_after_header(b, headers, limit)
    }

    pub fn from_armor_after_header<R: BufRead>(
        mut b: R,
        headers: Headers,
        limit: usize,
    ) -> Result<(Self, Headers)> {
        let hashes = validate_headers(headers)?;

        debug!("Found Hash headers: {hashes:?}");

        // Cleartext Body
        let (csf_encoded_text, prefix) = read_cleartext_body(&mut b)?;
        let b = std::io::Cursor::new(prefix).chain(b);

        // Signatures
        let mut dearmor = armor::Dearmor::with_limit(b, limit);
        dearmor.read_header()?;
        // Safe to unwrap, as read_header succeeded.
        let typ = dearmor
            .typ
            .ok_or_else(|| format_err!("dearmor failed to retrieve armor type"))?;

        ensure_eq!(typ, BlockType::Signature, "invalid block type");

        // TODO: limited read to 1GiB
        let mut bytes = Vec::new();
        dearmor.read_to_end(&mut bytes)?;

        let signatures = StandaloneSignature::from_bytes_many(&bytes[..])?;
        let signatures = signatures.collect::<Result<_>>()?;

        let (_, headers, _, b) = dearmor.into_parts();

        if has_rest(b)? {
            bail!("unexpected trailing data");
        }

        Ok((
            Self {
                csf_encoded_text,
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
        writer.write_all(b"\n")?;

        // Hashes
        for hash in &self.hashes {
            writer.write_all(b"Hash: ")?;
            writer.write_all(hash.to_string().as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(b"\n")?;

        // Cleartext body
        writer.write_all(self.csf_encoded_text.as_bytes())?;
        writer.write_all(b"\n")?;

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

fn validate_headers(headers: Headers) -> Result<Vec<HashAlgorithm>> {
    let mut hashes = Vec::new();
    for (name, values) in headers {
        ensure_eq!(name, "Hash", "unexpected header");
        for value in values {
            let h: HashAlgorithm = value
                .parse()
                .map_err(|_| format_err!("unknown hash algorithm {}", value))?;
            hashes.push(h);
        }
    }
    Ok(hashes)
}

/// Dash escape the given text.
///
/// This implementation is implicitly agnostic between "\n" and "\r\n" line endings.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-dash-escaped-text>
fn dash_escape(text: &str) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with('-') {
            out += "- ";
        }
        out.push_str(line);
    }

    out
}

/// Undo dash escaping of `text`, and trim space/tabs at the end of lines.
///
/// This implementation can handle both "\n" and "\r\n" line endings.
fn dash_unescape_and_trim(text: &str) -> String {
    let mut out = String::new();

    for line in text.split_inclusive('\n') {
        // break each line into "content" and "line ending"
        let line_end_len = if line.ends_with("\r\n") {
            2
        } else if line.ends_with('\n') {
            1
        } else {
            0
        };
        let (content, end) = line.split_at(line.len() - line_end_len);

        // strip dash escapes if they exist
        let undashed = content.strip_prefix("- ").unwrap_or(content);

        // trim spaces/tabs from the end of line content
        let trimmed = undashed.trim_end_matches([' ', '\t']);

        // append normalized line content
        out += trimmed;

        // append line ending
        out += end;
    }

    out
}

/// Does the remaining buffer contain any non-whitespace characters?
fn has_rest<R: BufRead>(mut b: R) -> Result<bool> {
    let mut buf = [0u8; 64];
    while b.read(&mut buf)? > 0 {
        if buf.iter().any(|&c| !char::from(c).is_ascii_whitespace()) {
            return Ok(true);
        }
    }

    Ok(false)
}

const HEADER_LINE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

fn read_cleartext_body<B: BufRead>(b: &mut B) -> Result<(String, String)> {
    let mut out = String::new();

    loop {
        let read = b.read_line(&mut out)?;
        // early end
        if read == 0 {
            bail!("unexpected early end");
        }

        // Empty CSF message body
        if out.starts_with("-----") {
            return Ok(("".to_string(), out));
        }

        // Look for header start in the last line
        if let Some(pos) = out.rfind("\n-----") {
            // found our end
            let rest = out.split_off(pos + 1);
            // remove trailing line break
            if let Some(pos) = out.rfind("\r\n") {
                out.truncate(pos);
            } else {
                out.truncate(out.len() - 1);
            }
            return Ok((out, rest));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::composed::{Any, SignedPublicKey, SignedSecretKey};

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
    fn test_cleartext_interop_testsuite_1_good() {
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
            msg.signed_text(),
            "From the grocery store we need:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n\r\n"
        );

        let key_data = std::fs::read_to_string("./tests/unit-tests/cleartext-key-01.asc").unwrap();
        let (key, _) = SignedSecretKey::from_string(&key_data).unwrap();

        msg.verify(&*key.public_key()).unwrap();
        assert_eq!(msg.signatures().len(), 1);

        roundtrip(&data, &msg, &headers);
    }

    #[test]
    fn test_cleartext_interop_testsuite_1_any() {
        let _ = pretty_env_logger::try_init();

        let data = std::fs::read_to_string("./tests/unit-tests/cleartext-msg-01.asc").unwrap();

        let (msg, headers) = CleartextSignedMessage::from_string(&data).unwrap();

        let (any, headers2) = Any::from_string(&data).unwrap();
        assert_eq!(headers, headers2);

        if let Any::Cleartext(msg2) = any {
            assert_eq!(msg, msg2);
        } else {
            panic!("got unexpected type of any: {any:?}");
        }
    }

    #[test]
    fn test_cleartext_interop_testsuite_1_fail() {
        let _ = pretty_env_logger::try_init();

        let data = std::fs::read_to_string("./tests/unit-tests/cleartext-msg-01-fail.asc").unwrap();

        let err = CleartextSignedMessage::from_string(&data).unwrap_err();
        dbg!(err);

        let err = Any::from_string(&data).unwrap_err();
        dbg!(err);
    }

    #[test]
    fn test_cleartext_interop_testsuite_2_fail() {
        let _ = pretty_env_logger::try_init();

        let data = std::fs::read_to_string("./tests/unit-tests/cleartext-msg-02-fail.asc").unwrap();

        let err = CleartextSignedMessage::from_string(&data).unwrap_err();
        dbg!(err);

        let err = Any::from_string(&data).unwrap_err();
        dbg!(err);
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
        let mut data = std::io::Cursor::new(b"-- hello\n--world\n-----bla");
        assert_eq!(
            read_cleartext_body(&mut data).unwrap(),
            ("-- hello\n--world".to_string(), "-----bla".to_string()),
        );

        let mut data = std::io::Cursor::new(b"-- hello\r\n--world\r\n-----bla");
        assert_eq!(
            read_cleartext_body(&mut data).unwrap(),
            ("-- hello\r\n--world".to_string(), "-----bla".to_string()),
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

        assert_eq!(dash_escape(input), expected);
    }

    #[test]
    fn test_dash_unescape_and_trim() {
        let input = "From the grocery store we need:

- - tofu\u{20}\u{20}
- - vegetables\t
- - noodles

";
        let expected = "From the grocery store we need:

- tofu
- vegetables
- noodles

";

        assert_eq!(dash_unescape_and_trim(input), expected);
    }

    #[test]
    fn test_dash_unescape_and_trim2() {
        let input = "From the grocery store we need:

- - tofu\u{20}\u{20}
- - vegetables\t
- - noodles
-\u{20}
- ";
        let expected = "From the grocery store we need:

- tofu
- vegetables
- noodles

";

        assert_eq!(dash_unescape_and_trim(input), expected);
    }

    #[test]
    fn test_sign() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let key_data = std::fs::read_to_string("./tests/unit-tests/cleartext-key-01.asc").unwrap();
        let (key, _) = SignedSecretKey::from_string(&key_data).unwrap();
        let msg = CleartextSignedMessage::sign(
            &mut rng,
            "hello\n-world-what-\nis up\n",
            &*key,
            &Password::empty(),
        )
        .unwrap();
        msg.verify(&*key.public_key()).unwrap();
    }

    #[test]
    fn test_sign_no_newline() {
        const MSG: &str = "message without newline at the end";
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let key_data = std::fs::read_to_string("./tests/unit-tests/cleartext-key-01.asc").unwrap();
        let (key, _) = SignedSecretKey::from_string(&key_data).unwrap();
        let msg = CleartextSignedMessage::sign(&mut rng, MSG, &*key, &Password::empty()).unwrap();

        assert_eq!(msg.signed_text(), MSG);

        msg.verify(&*key.public_key()).unwrap();
    }

    #[test]
    fn test_load_big_csf() {
        let msg_data = std::fs::read_to_string("./tests/unit-tests/csf-puppet/InRelease").unwrap();

        // FIXME: this fails to read -> buffer_redux problem!?
        let (_msg, _) = CleartextSignedMessage::from_armor(msg_data.as_bytes()).unwrap();
    }

    #[test]
    fn test_verify_csf_puppet() {
        // test data via https://github.com/rpgp/rpgp/issues/424

        let msg_data = std::fs::read_to_string("./tests/unit-tests/csf-puppet/InRelease").unwrap();
        let (Any::Cleartext(msg), headers) = Any::from_string(&msg_data).unwrap() else {
            panic!("couldn't read msg")
        };

        // superficially look at message
        assert_eq!(headers.len(), 0);
        assert_eq!(msg.signatures().len(), 1);
        roundtrip(&msg_data, &msg, &headers);

        // validate signature
        let cert_data =
            std::fs::read_to_string("./tests/unit-tests/csf-puppet/DEB-GPG-KEY-puppet-20250406")
                .unwrap();
        let (cert, _) = SignedPublicKey::from_string(&cert_data).unwrap();

        msg.verify(&cert).expect("verify");
    }
}
