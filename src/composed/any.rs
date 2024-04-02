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
        let (typ, headers, rest) = dearmor.read_only_header()?;

        match typ {
            // Standard PGP types
            BlockType::PublicKey => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest);
                let key = SignedPublicKey::from_bytes(dearmor)?;
                Ok((Self::PublicKey(key), headers))
            }
            BlockType::PrivateKey => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest);
                let key = SignedSecretKey::from_bytes(dearmor)?;
                Ok((Self::SecretKey(key), headers))
            }
            BlockType::Message => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest);
                let msg = Message::from_bytes(dearmor)?;
                Ok((Self::Message(msg), headers))
            }
            BlockType::Signature => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest);
                let sig = StandaloneSignature::from_bytes(dearmor)?;
                Ok((Self::Signature(sig), headers))
            }
            BlockType::CleartextMessage => {
                let (sig, headers) =
                    CleartextSignedMessage::from_armor_after_header(rest, headers)?;
                Ok((Self::Cleartext(sig), headers))
            }
            _ => unimplemented_err!("unsupported block type: {}", typ),
        }
    }
}
