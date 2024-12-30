use std::io::{BufRead, Read};

use buffer_redux::BufReader;

use crate::{
    armor::{self, BlockType, Dearmor},
    cleartext::CleartextSignedMessage,
    errors::Result,
    Deserializable, Message, SignedPublicKey, SignedSecretKey, StandaloneSignature,
};

/// A flexible representation of what can be represented in an armor file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Any {
    Cleartext(CleartextSignedMessage),
    PublicKey(SignedPublicKey),
    SecretKey(SignedSecretKey),
    Message(Message),
    Signature(StandaloneSignature),
}

impl Any {
    /// Parse armored ascii data.
    pub fn from_armor(bytes: impl Read) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(BufReader::new(bytes))
    }

    /// Parse a single armor encoded composition.
    pub fn from_string(input: &str) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(input.as_bytes())
    }

    /// Parse armored ascii data.
    pub fn from_armor_buf<R: BufRead>(input: R) -> Result<(Self, armor::Headers)> {
        let dearmor = armor::Dearmor::new(input);
        let limit = dearmor.max_buffer_limit();
        let (typ, headers, has_leading_data, rest) = dearmor.read_only_header()?;
        match typ {
            // Standard PGP types
            BlockType::PublicKey => {
                let mut dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                // TODO: limited read to 1GiB
                let mut bytes = Vec::new();
                dearmor.read_to_end(&mut bytes)?;
                let key = SignedPublicKey::from_bytes(bytes.into())?;
                Ok((Self::PublicKey(key), headers))
            }
            BlockType::PrivateKey => {
                let mut dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                // TODO: limited read to 1GiB
                let mut bytes = Vec::new();
                dearmor.read_to_end(&mut bytes)?;
                let key = SignedSecretKey::from_bytes(bytes.into())?;
                Ok((Self::SecretKey(key), headers))
            }
            BlockType::Message => {
                let mut dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                // TODO: limited read to 1GiB
                let mut bytes = Vec::new();
                dearmor.read_to_end(&mut bytes)?;
                let msg = Message::from_bytes(bytes.into())?;
                Ok((Self::Message(msg), headers))
            }
            BlockType::Signature => {
                let mut dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                // TODO: limited read to 1GiB
                let mut bytes = Vec::new();
                dearmor.read_to_end(&mut bytes)?;
                let sig = StandaloneSignature::from_bytes(bytes.into())?;
                Ok((Self::Signature(sig), headers))
            }
            BlockType::CleartextMessage => {
                ensure!(
                    !has_leading_data,
                    "must not have leading data for a cleartext message"
                );
                let (sig, headers) =
                    CleartextSignedMessage::from_armor_after_header(rest, headers, limit)?;
                Ok((Self::Cleartext(sig), headers))
            }
            _ => unimplemented_err!("unsupported block type: {}", typ),
        }
    }
}
