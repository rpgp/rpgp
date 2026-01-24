use std::{io::Read, iter::Peekable};

use aead::rand_core::CryptoRng;

use crate::{
    armor,
    composed::{ArmorOptions, Deserializable, SubpacketConfig},
    crypto::hash::HashAlgorithm,
    errors::{bail, format_err, Result},
    packet::{Packet, PacketTrait, Signature, SignatureConfig, SignatureType},
    ser::Serialize,
    types::{KeyVersion, Password, SigningKey, Tag, VerifyingKey},
};

/// An OpenPGP data signature that occurs outside an OpenPGP Message,
/// as a detached signature:
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#detached-signatures>.
///
/// All [DetachedSignature]s are either of type [SignatureType::Binary] or [SignatureType::Text].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    pub signature: Signature,
}

impl DetachedSignature {
    pub fn new(signature: Signature) -> Self {
        DetachedSignature { signature }
    }

    /// Create a detached data signature over `data`, with [SignatureType::Binary].
    pub fn sign_binary_data<RNG: CryptoRng + ?Sized, R: Read>(
        rng: &mut RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Binary,
            key,
            key_pw,
            hash_algorithm,
            data,
            SubpacketConfig::Default,
        )
    }

    /// Create a detached data signature over `data`, with [SignatureType::Binary],
    /// with explicit subpacket configuration.
    ///
    /// This gives callers full control of the hashed and unhashed subpacket areas.
    pub fn sign_binary_data_with_subpackets<RNG: CryptoRng + ?Sized, R: Read>(
        rng: &mut RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Binary,
            key,
            key_pw,
            hash_algorithm,
            data,
            subpackets,
        )
    }

    /// Create a detached data signature over `data`, with [SignatureType::Text].
    ///
    /// Using [SignatureType::Text] makes the signature stable against changes of line ending
    /// encodings. The signature is not invalidated if the plaintext is e.g. changed between using
    /// "LF" line endings or "CR+LF" line endings.
    pub fn sign_text_data<RNG: CryptoRng + ?Sized, R: Read>(
        rng: &mut RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Text,
            key,
            key_pw,
            hash_algorithm,
            data,
            SubpacketConfig::Default,
        )
    }

    /// Create a detached data signature over `data`, with [SignatureType::Text],
    /// with explicit subpacket configuration.
    ///
    /// This gives callers full control of the hashed and unhashed subpacket areas.
    ///
    /// Using [SignatureType::Text] makes the signature stable against changes of line ending
    /// encodings. The signature is not invalidated if the plaintext is e.g. changed between using
    /// "LF" line endings or "CR+LF" line endings.
    pub fn sign_text_data_with_subpackets<RNG: CryptoRng + ?Sized, R: Read>(
        rng: &mut RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Text,
            key,
            key_pw,
            hash_algorithm,
            data,
            subpackets,
        )
    }

    fn sign_data<RNG: CryptoRng + ?Sized, R: Read>(
        rng: &mut RNG,
        typ: SignatureType,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        let mut config = match key.version() {
            KeyVersion::V4 => SignatureConfig::v4(typ, key.algorithm(), hash_algorithm),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, key.algorithm(), hash_algorithm)?,
            v => bail!("unsupported key version: {:?}", v),
        };

        let (hashed, unhashed) = subpackets.to_subpackets(key)?;
        config.hashed_subpackets = hashed;
        config.unhashed_subpackets = unhashed;

        let sig = config.sign(key, key_pw, data)?;

        Ok(DetachedSignature::new(sig))
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )
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

    /// Verify this signature.
    pub fn verify(&self, key: &impl VerifyingKey, content: &[u8]) -> Result<()> {
        self.signature.verify(key, content)
    }
}

impl Serialize for DetachedSignature {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.signature.to_writer_with_header(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.signature.write_len_with_header()
    }
}

impl Deserializable for DetachedSignature {
    /// Parse a signature.
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignatureParser { source: packets })
    }

    fn matches_block_type(typ: armor::BlockType) -> bool {
        matches!(typ, armor::BlockType::Signature)
    }
}

pub struct SignatureParser<I: Sized + Iterator<Item = Result<Packet>>> {
    source: Peekable<I>,
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for SignatureParser<I> {
    type Item = Result<DetachedSignature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Result<Packet>>>(
    packets: &mut Peekable<I>,
) -> Option<Result<DetachedSignature>> {
    match packets.by_ref().next() {
        Some(Ok(packet)) => match packet.tag() {
            Tag::Signature => Some(packet.try_into().map(DetachedSignature::new)),
            _ => Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        },
        Some(Err(e)) => Some(Err(e)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use chacha20::ChaCha20Rng;
    use rand::SeedableRng;

    use crate::{
        composed::{Deserializable, DetachedSignature, SignedSecretKey, SubpacketConfig},
        crypto::hash::HashAlgorithm,
        packet::{Subpacket, SubpacketData},
        types::{KeyDetails, Password, Timestamp},
    };

    const PLAIN: &str = "hello world\r\n";
    const PLAIN_LF: &str = "hello world\n";

    #[test]
    fn detached_signature_binary() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (alice, _) =
            SignedSecretKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.sec.asc")
                .unwrap();

        let sig = DetachedSignature::sign_binary_data(
            &mut rng,
            &alice.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            PLAIN.as_bytes(),
        )
        .unwrap();

        sig.verify(alice.primary_key.public_key(), PLAIN.as_bytes())
            .expect("verify ok");

        // inspect the signature for the expected subpacket structure
        let cfg = sig.signature.config().unwrap();

        assert_eq!(cfg.hashed_subpackets.len(), 2);
        assert_eq!(cfg.unhashed_subpackets.len(), 1);

        assert_eq!(sig.signature.issuer_fingerprint().len(), 1);
        assert_eq!(sig.signature.issuer_key_id().len(), 1);

        // differently normalized plaintext should not verify for SignatureType::Binary
        sig.verify(alice.primary_key.public_key(), PLAIN_LF.as_bytes())
            .expect_err("verify with unnormalized line ending not ok");
    }

    #[test]
    fn detached_signature_text() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (alice, _) =
            SignedSecretKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.sec.asc")
                .unwrap();

        let sig = DetachedSignature::sign_text_data(
            &mut rng,
            &alice.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            PLAIN.as_bytes(),
        )
        .unwrap();

        sig.verify(alice.primary_key.public_key(), PLAIN.as_bytes())
            .expect("verify ok");

        // inspect the signature for the expected subpacket structure
        let cfg = sig.signature.config().unwrap();

        assert_eq!(cfg.hashed_subpackets.len(), 2);
        assert_eq!(cfg.unhashed_subpackets.len(), 1);

        assert_eq!(sig.signature.issuer_fingerprint().len(), 1);
        assert_eq!(sig.signature.issuer_key_id().len(), 1);

        // differently normalized plaintext should verify as ok for SignatureType::Text
        sig.verify(alice.primary_key.public_key(), PLAIN_LF.as_bytes())
            .expect("verify with unnormalized line ending is ok in text mode");
    }

    #[test]
    fn detached_signature_binary_with_subpackets() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (alice, _) =
            SignedSecretKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.sec.asc")
                .unwrap();

        let hashed = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(alice.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::PolicyURI("foo".into())).unwrap(),
        ];

        let sig = DetachedSignature::sign_binary_data_with_subpackets(
            &mut rng,
            &alice.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            PLAIN.as_bytes(),
            SubpacketConfig::UserDefined {
                hashed,
                unhashed: vec![],
            },
        )
        .unwrap();

        sig.verify(alice.primary_key.public_key(), PLAIN.as_bytes())
            .expect("verify ok");

        // inspect the signature for the expected subpacket structure
        let cfg = sig.signature.config().unwrap();

        assert_eq!(cfg.hashed_subpackets.len(), 3);
        assert!(cfg.unhashed_subpackets.is_empty());

        // differently normalized plaintext should not verify for SignatureType::Binary
        sig.verify(alice.primary_key.public_key(), PLAIN_LF.as_bytes())
            .expect_err("verify with unnormalized line ending not ok");
    }

    #[test]
    fn detached_signature_text_with_subpackets() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (alice, _) =
            SignedSecretKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.sec.asc")
                .unwrap();

        let hashed = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(alice.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::PolicyURI("foo".into())).unwrap(),
        ];

        let sig = DetachedSignature::sign_text_data_with_subpackets(
            &mut rng,
            &alice.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            PLAIN.as_bytes(),
            SubpacketConfig::UserDefined {
                hashed,
                unhashed: vec![],
            },
        )
        .unwrap();

        sig.verify(alice.primary_key.public_key(), PLAIN.as_bytes())
            .expect("verify ok");

        // inspect the signature for the expected subpacket structure
        let cfg = sig.signature.config().unwrap();

        assert_eq!(cfg.hashed_subpackets.len(), 3);
        assert!(cfg.unhashed_subpackets.is_empty());

        // differently normalized plaintext should verify as ok for SignatureType::Text
        sig.verify(alice.primary_key.public_key(), PLAIN_LF.as_bytes())
            .expect("verify with unnormalized line ending is ok in text mode");
    }
}
