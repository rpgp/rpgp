use armor::{self, BlockType};
use errors::{Error, Result};
use packet::{self, types};
use std::io::{Cursor, Read};

pub trait Deserializable: Sized {
    /// Parse a single byte encoded composition.
    fn from_bytes(bytes: impl Read) -> Result<Self> {
        let el = Self::from_bytes_many(bytes)?;

        if el.len() > 1 {
            return Err(Error::MultipleKeys);
        }

        el.into_iter().nth(0).ok_or_else(|| Error::NoKey)
    }

    /// Parse a single armor encoded composition.
    fn from_string(input: &str) -> Result<Self> {
        let el = Self::from_string_many(input)?;

        if el.len() > 1 {
            return Err(Error::MultipleKeys);
        }

        el.into_iter().nth(0).ok_or_else(|| Error::NoKey)
    }

    /// Parse an armor encoded list of compositions.
    fn from_string_many(input: &str) -> Result<Vec<Self>> {
        let mut c = Cursor::new(input);

        Self::from_armor_many(&mut c)
    }

    /// Armored ascii data.
    fn from_armor_single(input: impl Read) -> Result<Self> {
        let el = Self::from_armor_many(input)?;

        if el.len() > 1 {
            // TODO: rename to non key specific
            return Err(Error::MultipleKeys);
        }

        el.into_iter().nth(0).ok_or_else(|| Error::NoKey)
    }

    /// Armored ascii data.
    fn from_armor_many(input: impl Read) -> Result<Vec<Self>> {
        let (typ, _headers, body) = armor::parse(input)?;
        // TODO: add typ and headers information to the key possibly?
        match typ {
            // Standard PGP types
            BlockType::PublicKey
            | BlockType::PrivateKey
            | BlockType::Message
            | BlockType::MultiPartMessage(_, _)
            | BlockType::Signature
            | BlockType::File => {
                // TODO: check that the result is what it actually said.
                Self::from_bytes_many(body.as_slice())
            }
            BlockType::PublicKeyPKCS1
            | BlockType::PublicKeyPKCS8
            | BlockType::PublicKeyOpenssh
            | BlockType::PrivateKeyPKCS1
            | BlockType::PrivateKeyPKCS8
            | BlockType::PrivateKeyOpenssh => {
                unimplemented_err!("key format {:?}", typ);
            }
        }
    }

    /// Parse a list of compositions in raw byte format.
    fn from_bytes_many(bytes: impl Read) -> Result<Vec<Self>> {
        let packets = packet::parser(bytes)?;

        Self::from_packets(&packets)
    }

    /// Turn a list of packets into a usable representation.
    fn from_packets<'a>(impl IntoIterator<Item = &'a types::Packet>) -> Result<Vec<Self>>;
}
