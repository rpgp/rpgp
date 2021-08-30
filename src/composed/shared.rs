use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};

use crate::armor::{self, BlockType};
use crate::errors::{Error, Result};
use crate::packet::{Packet, PacketParser};

pub trait Deserializable: Sized {
    /// Parse a single byte encoded composition.
    fn from_bytes(bytes: impl Read) -> Result<Self> {
        let mut el = Self::from_bytes_many(bytes);
        el.next().ok_or(Error::NoMatchingPacket)?
    }

    /// Parse a single armor encoded composition.
    fn from_string(input: &str) -> Result<(Self, BTreeMap<String, String>)> {
        let (mut el, headers) = Self::from_string_many(input)?;
        Ok((el.next().ok_or(Error::NoMatchingPacket)??, headers))
    }

    /// Parse an armor encoded list of compositions.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    fn from_string_many<'a>(
        input: &'a str,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        BTreeMap<String, String>,
    )> {
        Self::from_armor_many(Cursor::new(input))
    }

    /// Armored ascii data.
    fn from_armor_single<R: Read + Seek>(input: R) -> Result<(Self, BTreeMap<String, String>)> {
        let (mut el, headers) = Self::from_armor_many(input)?;
        Ok((el.next().ok_or(Error::NoMatchingPacket)??, headers))
    }

    /// Armored ascii data.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    fn from_armor_many<'a, R: Read + Seek + 'a>(
        input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        BTreeMap<String, String>,
    )> {
        let mut dearmor = armor::Dearmor::new(input);
        dearmor.read_header()?;
        // Safe to unwrap, as read_header succeeded.
        let typ = dearmor
            .typ
            .ok_or_else(|| format_err!("dearmor failed to retrieve armor type"))?;

        // TODO: add typ information to the key possibly?
        match typ {
            // Standard PGP types
            BlockType::PublicKey
            | BlockType::PrivateKey
            | BlockType::Message
            | BlockType::MultiPartMessage(_, _)
            | BlockType::Signature
            | BlockType::File => {
                let headers = dearmor.headers.clone(); // FIXME: avoid clone

                // TODO: check that the result is what it actually said.
                Ok((Self::from_bytes_many(dearmor), headers))
            }
            BlockType::PublicKeyPKCS1(_)
            | BlockType::PublicKeyPKCS8
            | BlockType::PublicKeyOpenssh
            | BlockType::PrivateKeyPKCS1(_)
            | BlockType::PrivateKeyPKCS8
            | BlockType::PrivateKeyOpenssh => {
                unimplemented_err!("key format {:?}", typ);
            }
        }
    }

    /// Parse a list of compositions in raw byte format.
    fn from_bytes_many<'a>(bytes: impl Read + 'a) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        let packets = PacketParser::new(bytes).filter_map(|p| {
            // for now we are skipping any packets that we failed to parse
            if p.is_ok() {
                p.ok()
            } else {
                warn!("skipping packet: {:?}", p);
                None
            }
        });

        Self::from_packets(packets)
    }

    /// Turn a list of packets into a usable representation.
    fn from_packets<'a>(
        packets: impl Iterator<Item = Packet> + 'a,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a>;
}
