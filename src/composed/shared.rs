use byteorder::ReadBytesExt;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

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
        let packets = PacketParser::new(bytes).filter_map(filter_parsed_packet_results);

        Self::from_packets(packets.peekable())
    }

    /// Turn a list of packets into a usable representation.
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a>;

    /// Parses a single composition, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns a composition and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    fn from_reader_single<'a, R: Read + Seek + 'a>(
        mut input: R,
    ) -> Result<(Self, Option<BTreeMap<String, String>>)> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_single(input)?;
            Ok((keys, Some(headers)))
        } else {
            Ok((Self::from_bytes(input)?, None))
        }
    }

    /// Parses a list of compositions, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns an iterator of compositions and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    fn from_reader_many<'a, R: Read + Seek + 'a>(
        mut input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        Option<BTreeMap<String, String>>,
    )> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_many(input)?;
            Ok((keys, Some(headers)))
        } else {
            Ok((Self::from_bytes_many(input), None))
        }
    }
}

/// Process results from low level packet parser:
///
/// - Skip Marker packets.
/// - Pass through other packets.
/// - Skip any `Error::Unsupported`, those were marked as "safe to ignore" by the low level parser.
/// - Skip `Error::Incomplete`
/// - Skip `Error::EllipticCurve`
/// - Pass through other errors.
pub(crate) fn filter_parsed_packet_results(p: Result<Packet>) -> Option<Result<Packet>> {
    match &p {
        Ok(Packet::Marker(_m)) => {
            debug!("skipping marker packet");
            None
        }
        Ok(_) => Some(p),
        Err(e) => {
            if let Error::InvalidPacketContent(b) = &e {
                let err: &Error = b; // unbox
                if let Error::Unsupported(e) = err {
                    // "Error::Unsupported" signals parser errors that we can safely ignore
                    // (e.g. packets with unsupported versions)
                    warn!("skipping unsupported packet: {p:?}");
                    debug!("error: {e:?}");
                    return None;
                }
                if let Error::EllipticCurve(e) = err {
                    // this error happens in one SKS test key, presumably bad public key material.
                    // ignoring the packet seems safe.
                    warn!("skipping bad elliptic curve data: {p:?}");
                    debug!("error: {e:?}");
                    return None;
                }
            }
            if let Error::Incomplete(_i) = e {
                // We ignore incomplete packets for now (some of these occur in the SKS dumps under `tests`)
                warn!("skipping incomplete packet: {p:?}");
                return None;
            }

            // Pass through all other errors from the low level parser, they should be surfaced
            Some(Err(Error::Message(format!(
                "unexpected packet data: {e:?}"
            ))))
        }
    }
}

/// Check if the OpenPGP data in `input` seems to be ASCII-armored or binary (by looking at the
/// highest bit of the first byte)
pub(crate) fn is_binary<R: Read + Seek>(input: &mut R) -> Result<bool> {
    // Peek at the first byte in the reader
    let first = input.read_u8()?;
    let _ = input.seek(SeekFrom::Current(-1))?;

    // If the first bit of the first byte is set, we assume this is binary OpenPGP data, otherwise
    // we assume it is ASCII-armored.
    let binary = first & 0x80 != 0;

    Ok(binary)
}
