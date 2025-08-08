use std::{io::Read, iter::Peekable};

use aead::rand_core::CryptoRng;
use chrono::{SubsecRound, Utc};
use rand::Rng;

use crate::{
    armor,
    composed::{ArmorOptions, Deserializable},
    crypto::hash::HashAlgorithm,
    errors::{bail, format_err, Result},
    packet::{
        Packet, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    },
    ser::Serialize,
    types::{KeyVersion, Password, PublicKeyTrait, SecretKeyTrait, Tag},
};

/// An OpenPGP data signature that occurs outside an OpenPGP Message.
///
/// Can be used either for "detached signatures":
/// <https://www.rfc-editor.org/rfc/rfc9580.html#detached-signatures>.
///
/// Or in the context of a Cleartext Signature:
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo>
///
/// All [StandaloneSignature]s are either of type [SignatureType::Binary] or [SignatureType::Text].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneSignature {
    pub signature: Signature,
}

impl StandaloneSignature {
    pub fn new(signature: Signature) -> Self {
        StandaloneSignature { signature }
    }

    /// Create a "detached" data signature over `data`, with [SignatureType::Binary].
    pub fn sign_binary_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<StandaloneSignature> {
        Self::sign_data(
            rng,
            SignatureType::Binary,
            key,
            key_pw,
            hash_algorithm,
            data,
        )
    }

    /// Create a "detached" data signature over `data`, with [SignatureType::Text].
    ///
    /// Using [SignatureType::Text] makes the signature stable against changes of line ending
    /// encodings. The signature is not invalidated if the plaintext is e.g. changed between using
    /// "LF" line endings or "CR+LF" line endings.
    pub fn sign_text_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<StandaloneSignature> {
        Self::sign_data(rng, SignatureType::Text, key, key_pw, hash_algorithm, data)
    }

    fn sign_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        typ: SignatureType,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<StandaloneSignature> {
        let mut config = match key.version() {
            KeyVersion::V4 => SignatureConfig::v4(typ, key.algorithm(), hash_algorithm),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, key.algorithm(), hash_algorithm)?,
            v => bail!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                Utc::now().trunc_subsecs(0),
            ))?,
        ];

        if key.version() < KeyVersion::V6 {
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];
        }

        let sig = config.sign(key, key_pw, data)?;

        Ok(StandaloneSignature::new(sig))
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
    pub fn verify(&self, key: &impl PublicKeyTrait, content: &[u8]) -> Result<()> {
        self.signature.verify(key, content)
    }
}

impl Serialize for StandaloneSignature {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.signature.to_writer_with_header(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.signature.write_len_with_header()
    }
}

impl Deserializable for StandaloneSignature {
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
    type Item = Result<StandaloneSignature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Result<Packet>>>(
    packets: &mut Peekable<I>,
) -> Option<Result<StandaloneSignature>> {
    match packets.by_ref().next() {
        Some(Ok(packet)) => match packet.tag() {
            Tag::Signature => Some(packet.try_into().map(StandaloneSignature::new)),
            _ => Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        },
        Some(Err(e)) => Some(Err(e)),
        None => None,
    }
}
