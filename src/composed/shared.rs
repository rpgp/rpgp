use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
};

use log::{debug, warn};

use crate::{
    armor::{self, BlockType},
    errors::{bail, format_err, unimplemented_err, Error, Result},
    packet::{Packet, PacketParser},
};

pub trait Deserializable: Sized {
    /// Parse a single byte encoded composition.
    fn from_bytes<R: BufRead>(bytes: R) -> Result<Self> {
        let mut el = Self::from_bytes_many(bytes)?;
        el.next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())?
    }

    /// Parse a single armor encoded composition.
    fn from_string(input: &str) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_string_many(input)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    /// Parse an armor encoded list of compositions.
    #[allow(clippy::type_complexity)]
    fn from_string_many<'a>(
        input: &'a str,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        Self::from_armor_many_buf(input.as_bytes())
    }

    /// Armored ascii data.
    fn from_armor_single<R: Read>(input: R) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_many(input)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    /// Armored ascii data.
    fn from_armor_single_buf<R: BufRead>(input: R) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_many_buf(input)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    /// Armored ascii data.
    #[allow(clippy::type_complexity)]
    fn from_armor_many<'a, R: Read + 'a>(
        input: R,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        Self::from_armor_many_buf(BufReader::new(input))
    }

    #[allow(clippy::type_complexity)]
    fn from_armor_many_buf<'a, R: BufRead + 'a>(
        input: R,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
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
            | BlockType::CleartextMessage
            | BlockType::File => {
                let headers = dearmor.headers.clone(); // FIXME: avoid clone

                if !Self::matches_block_type(typ) {
                    bail!("unexpected block type: {}", typ);
                }

                Ok((Self::from_bytes_many(BufReader::new(dearmor))?, headers))
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
    fn from_bytes_many<'a, R: BufRead + 'a>(
        bytes: R,
    ) -> Result<Box<dyn Iterator<Item = Result<Self>> + 'a>> {
        let packets = PacketParser::new(bytes)
            .filter_map(crate::composed::shared::filter_parsed_packet_results)
            .peekable();

        Ok(Self::from_packets(packets))
    }

    /// Parse a single binary encoded composition.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut el = Self::from_file_many(path)?;
        el.next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())?
    }

    /// Parse a single armor encoded composition.
    fn from_armor_file<P: AsRef<Path>>(path: P) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_file_many(path)?;
        let el = el
            .next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??;
        Ok((el, headers))
    }

    /// Parse a single armor encoded composition.
    fn from_armor_file_many<P: AsRef<Path>>(
        path: P,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>>>, armor::Headers)> {
        let file = std::fs::File::open(path)?;
        Self::from_armor_many_buf(BufReader::new(file))
    }

    /// Ready binary packets from the given file.
    fn from_file_many<P: AsRef<Path>>(path: P) -> Result<Box<dyn Iterator<Item = Result<Self>>>> {
        let file = std::fs::File::open(path)?;
        Self::from_bytes_many(BufReader::new(file))
    }

    /// Turn a list of packets into a usable representation.
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a>;

    /// Check if the given typ is a valid block type for this type.
    fn matches_block_type(typ: BlockType) -> bool;

    /// Parses a single composition, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns a composition and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[allow(clippy::type_complexity)]
    fn from_reader_single<'a, R: Read + 'a>(input: R) -> Result<(Self, Option<armor::Headers>)> {
        Self::from_reader_single_buf(BufReader::new(input))
    }

    #[allow(clippy::type_complexity)]
    fn from_reader_single_buf<'a, R: BufRead + 'a>(
        mut input: R,
    ) -> Result<(Self, Option<armor::Headers>)> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_single(input)?;
            Ok((keys, Some(headers)))
        } else {
            let (mut el, headers) = Self::from_reader_many_buf(input)?;
            let packet = el
                .next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??;
            Ok((packet, headers))
        }
    }

    /// Parses a list of compositions, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns an iterator of compositions and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[allow(clippy::type_complexity)]
    fn from_reader_many<'a, R: Read + 'a>(
        input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        Option<armor::Headers>,
    )> {
        Self::from_reader_many_buf(BufReader::new(input))
    }

    /// Parses a list of compositions, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns an iterator of compositions and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[allow(clippy::type_complexity)]
    fn from_reader_many_buf<'a, R: BufRead + 'a>(
        mut input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        Option<armor::Headers>,
    )> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_many_buf(input)?;
            Ok((keys, Some(headers)))
        } else {
            Ok((Self::from_bytes_many(input)?, None))
        }
    }
}

/// Process results from low level packet parser:
///
/// - Skip Marker and Padding packets.
/// - Pass through other packets.
/// - Skip any `Error::Unsupported`, those were marked as "safe to ignore" by the low level parser.
/// - Skip `Error::Incomplete`
/// - Skip `Error::EllipticCurve`
/// - Pass through other errors.
pub(crate) fn filter_parsed_packet_results(p: Result<Packet>) -> Option<Result<Packet>> {
    // FIXME: handle criticality of packets from 9580 (error, if unsupported)

    match p {
        Ok(ref packet) => {
            if let Packet::Marker(_) = packet {
                debug!("skipping marker packet");
                return None;
            }
            if let Packet::Padding(_) = packet {
                debug!("skipping padding packet");
                return None;
            }
            Some(p)
        }
        Err(e) => {
            if let Error::Unsupported { ref message, .. } = e {
                // "Error::Unsupported" signals parser errors that we can safely ignore
                // (e.g. packets with unsupported versions)
                warn!("skipping unsupported packet: {e:?}");
                debug!("error: {message}");
                return None;
            }
            if let Error::InvalidPacketContent { ref source } = &e {
                let err: &Error = source; // unbox
                if let Error::Unsupported { message, .. } = err {
                    // "Error::Unsupported" signals parser errors that we can safely ignore
                    // (e.g. packets with unsupported versions)
                    warn!("skipping unsupported packet: {e:?}");
                    debug!("error: {message}");
                    return None;
                }
                if let Error::EllipticCurve { source, .. } = err {
                    // this error happens in one SKS test key, presumably bad public key material.
                    // ignoring the packet seems safe.
                    warn!("skipping bad elliptic curve data: {e:?}");
                    debug!("error: {source:?}");
                    return None;
                }
            }
            if let Error::PacketIncomplete { ref source, .. } = e {
                // We ignore incomplete packets for now (some of these occur in the SKS dumps under `tests`)
                warn!("skipping incomplete packet: {e:?}");
                debug!("error: {source:?}");
                return None;
            }

            // Pass through all other errors from the low level parser, they should be surfaced
            Some(Err(e))
        }
    }
}

/// Check if the OpenPGP data in `input` seems to be ASCII-armored or binary (by looking at the
/// highest bit of the first byte)
pub(crate) fn is_binary<R: BufRead>(input: &mut R) -> Result<bool> {
    // Peek at the first byte in the reader
    let buf = input.fill_buf()?;
    if buf.is_empty() {
        bail!("empty input");
    }

    // If the first bit of the first byte is set, we assume this is binary OpenPGP data, otherwise
    // we assume it is ASCII-armored.
    let binary = buf[0] & 0x80 != 0;

    Ok(binary)
}
