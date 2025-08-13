use std::io::{BufRead, BufReader, Read};

use crate::{
    armor::{self, BlockType, Dearmor, DearmorOptions},
    composed::{
        cleartext::CleartextSignedMessage, Deserializable, DetachedSignature, Message,
        SignedPublicKey, SignedSecretKey,
    },
    errors::{ensure, unimplemented_err, Result},
};

/// A flexible representation of what can be represented in an armor file.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Any<'a> {
    Cleartext(CleartextSignedMessage),
    PublicKey(SignedPublicKey),
    SecretKey(SignedSecretKey),
    Message(Message<'a>),
    Signature(DetachedSignature),
}

impl<'a> Any<'a> {
    /// Parse armored ascii data.
    pub fn from_armor<R: std::fmt::Debug + Read + 'a + Send>(
        bytes: R,
    ) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(BufReader::new(bytes))
    }

    /// Parse a single armor encoded composition.
    pub fn from_string(input: &'a str) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(input.as_bytes())
    }

    /// Parse armored ascii data.
    pub fn from_armor_buf<R: BufRead + std::fmt::Debug + 'a + Send>(
        input: R,
    ) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf_with_options(input, DearmorOptions::default())
    }

    /// Parse armored ascii data, with explicit options for dearmoring.
    pub fn from_armor_buf_with_options<R: BufRead + std::fmt::Debug + 'a + Send>(
        input: R,
        opt: DearmorOptions,
    ) -> Result<(Self, armor::Headers)> {
        let dearmor = armor::Dearmor::with_options(input, opt);
        let limit = dearmor.max_buffer_limit();
        let (typ, headers, has_leading_data, rest) = dearmor.read_only_header()?;
        match typ {
            // Standard PGP types
            BlockType::PublicKey => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                let key = SignedPublicKey::from_bytes(BufReader::new(dearmor))?;
                Ok((Self::PublicKey(key), headers))
            }
            BlockType::PrivateKey => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                let key = SignedSecretKey::from_bytes(BufReader::new(dearmor))?;
                Ok((Self::SecretKey(key), headers))
            }
            BlockType::Message => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                let msg = Message::from_bytes(BufReader::new(dearmor))?;
                Ok((Self::Message(msg), headers))
            }
            BlockType::Signature => {
                let dearmor = Dearmor::after_header(typ, headers.clone(), rest, limit);
                let sig = DetachedSignature::from_bytes(BufReader::new(dearmor))?;
                Ok((Self::Signature(sig), headers))
            }
            BlockType::CleartextMessage => {
                ensure!(
                    !has_leading_data,
                    "must not have leading data for a cleartext message"
                );
                let (sig, headers) =
                    CleartextSignedMessage::from_armor_after_header(rest, headers, opt)?;
                Ok((Self::Cleartext(sig), headers))
            }
            _ => unimplemented_err!("unsupported block type: {}", typ),
        }
    }
}
