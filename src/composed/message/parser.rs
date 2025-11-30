use std::{
    io::{BufRead, BufReader},
    path::Path,
};

use super::{
    reader::{
        CompressedDataReader, LiteralDataReader, SignatureBodyReader, SignatureOnePassManyReader,
        SignatureOnePassReader,
    },
    DebugBufRead, MessageReader, PacketBodyReader,
};
use crate::{
    armor::{BlockType, DearmorOptions},
    composed::{message::Message, shared::is_binary, Edata, Esk, SignaturePacket},
    errors::{bail, format_err, unimplemented_err, Result},
    packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig},
    parsing_reader::BufReadParsing,
    types::{PkeskVersion, SkeskVersion, Tag},
};

struct MessageParser<'a> {
    messages: Vec<SignaturePacket>,
    current: MessageParserState<'a>,
}

enum MessageParserState<'a> {
    Start {
        packets: crate::packet::PacketParser<MessageReader<'a>>,
        is_nested: usize,
    },
    Error,
}

impl<'a> MessageParser<'a> {
    pub(super) fn new(
        packets: crate::packet::PacketParser<MessageReader<'a>>,
        is_nested: usize,
    ) -> Self {
        Self {
            messages: Vec::new(),
            current: MessageParserState::Start { packets, is_nested },
        }
    }

    /// Parses a single message level
    pub(super) fn run(mut self) -> Result<Option<Message<'a>>> {
        loop {
            match std::mem::replace(&mut self.current, MessageParserState::Error) {
                MessageParserState::Start { packets, is_nested } => {
                    log::debug!("next: nesting: {is_nested}");
                    let Some(packet) = packets.next_owned() else {
                        return Ok(None);
                    };
                    let mut packet = packet?;

                    // Handle 1 OpenPGP Message per loop iteration
                    let tag = packet.packet_header().tag();
                    log::debug!("tag {:?}", tag);
                    match tag {
                        Tag::SymKeyEncryptedSessionKey
                        | Tag::PublicKeyEncryptedSessionKey
                        | Tag::SymEncryptedData
                        | Tag::SymEncryptedProtectedData
                        | Tag::GnupgAeadData => {
                            return Self::visit_esk(tag, packet, is_nested);
                        }
                        Tag::Signature => {
                            // (b) Signed Message
                            //   (1) Signature Packet, OpenPGP Message
                            //      - Signature Packet
                            //      - OpenPGP Message
                            let signature = crate::packet::Signature::try_from_reader(
                                packet.packet_header(),
                                &mut packet,
                            )?;
                            self.messages.push(SignaturePacket::Signature { signature });
                            self.current = MessageParserState::Start {
                                packets: crate::packet::PacketParser::new(packet.into_inner()),
                                is_nested: is_nested + 1,
                            };
                        }
                        Tag::OnePassSignature => {
                            //   (2) One-Pass Signed Message.
                            //      - OPS
                            //      - OpenPgp Message
                            //      - Signature Packet
                            let signature = crate::packet::OnePassSignature::try_from_reader(
                                packet.packet_header(),
                                &mut packet,
                            )?;
                            self.messages.push(SignaturePacket::Ops { signature });
                            self.current = MessageParserState::Start {
                                packets: crate::packet::PacketParser::new(packet.into_inner()),
                                is_nested: is_nested + 1,
                            };
                        }
                        Tag::CompressedData => {
                            // (c) Compressed Message
                            //   - Compressed Packet
                            let reader = CompressedDataReader::new(packet, false)?;
                            let message = Message::Compressed {
                                reader,
                                is_nested: is_nested > 0,
                            };
                            return self.finish(message, is_nested);
                        }
                        Tag::LiteralData => {
                            // (d) Literal Message
                            //   - Literal Packet
                            let reader = LiteralDataReader::new(packet)?;
                            let message = Message::Literal {
                                reader,
                                is_nested: is_nested > 0,
                            };
                            return self.finish(message, is_nested);
                        }
                        Tag::Padding => {
                            // drain reader
                            packet.drain()?;
                            self.current = MessageParserState::Start {
                                packets: crate::packet::PacketParser::new(packet.into_inner()),
                                is_nested,
                            };
                        }
                        Tag::Marker => {
                            // drain reader
                            packet.drain()?;
                            self.current = MessageParserState::Start {
                                packets: crate::packet::PacketParser::new(packet.into_inner()),
                                is_nested,
                            };
                        }
                        Tag::UnassignedNonCritical(_) | Tag::Experimental(_) => {
                            // Skip "Unassigned Non-Critical" and "Private or Experimental Use" packets

                            // drain reader
                            packet.drain()?;
                            self.current = MessageParserState::Start {
                                packets: crate::packet::PacketParser::new(packet.into_inner()),
                                is_nested,
                            };
                        }
                        _ => {
                            bail!("unexpected packet type: {:?}", tag);
                        }
                    }
                }
                MessageParserState::Error => panic!("invalid parser state"),
            }
        }
    }

    fn finish(mut self, mut message: Message<'a>, is_nested: usize) -> Result<Option<Message<'a>>> {
        if self.messages.is_empty() {
            return Ok(Some(message));
        }

        let reader = SignatureOnePassManyReader::new(self.messages, Box::new(message))?;
        Ok(Some(Message::SignedOnePass {
            reader,
            is_nested: is_nested > 0, // TODO
        }))
    }

    fn visit_esk(
        tag: Tag,
        mut packet: PacketBodyReader<MessageReader<'a>>,
        is_nested: usize,
    ) -> Result<Option<Message<'a>>> {
        // (a) Encrypted Message:
        //   - ESK Seq (may be empty)
        //   - Encrypted Data -> OpenPGP Message

        let mut esks = Vec::new();

        if tag == Tag::SymKeyEncryptedSessionKey || tag == Tag::PublicKeyEncryptedSessionKey {
            let esk = Esk::try_from_reader(&mut packet)?;
            esks.push(esk);
        } else {
            // this message consists of just a bare encryption container
            let edata = Edata::try_from_reader(packet)?;

            return Ok(Some(Message::Encrypted {
                esk: esks, // empty
                edata,
                is_nested: is_nested > 0,
            }));
        }

        let mut packets = crate::packet::PacketParser::new(packet.into_inner());
        // Read ESKs unit we find the Encrypted Data
        loop {
            let Some(packet) = packets.next_owned() else {
                bail!("missing encrypted data packet");
            };

            let mut packet = packet?;
            let tag = packet.packet_header().tag();
            match tag {
                Tag::SymKeyEncryptedSessionKey | Tag::PublicKeyEncryptedSessionKey => {
                    let esk = Esk::try_from_reader(&mut packet)?;
                    esks.push(esk);
                    packets = crate::packet::PacketParser::new(packet.into_inner());
                }
                Tag::SymEncryptedData | Tag::SymEncryptedProtectedData | Tag::GnupgAeadData => {
                    let edata = Edata::try_from_reader(packet)?;
                    let esk = match edata {
                        Edata::SymEncryptedData { .. } => {
                            esk_filter(esks, PkeskVersion::V3, &[SkeskVersion::V4])
                        }
                        Edata::SymEncryptedProtectedData { ref reader } => match reader.config() {
                            ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1) => {
                                esk_filter(esks, PkeskVersion::V3, &[SkeskVersion::V4])
                            }

                            ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V2 {
                                ..
                            }) => esk_filter(esks, PkeskVersion::V6, &[SkeskVersion::V6]),
                            ProtectedDataConfig::GnupgAead { .. } => {
                                bail!("GnupgAead config not allowed in SymEncryptedProtectedData")
                            }
                        },
                        Edata::GnupgAeadData { ref reader, .. } => match reader.config() {
                            ProtectedDataConfig::Seipd(_) => {
                                bail!("Seipd config not allowed in GnupgAeadData");
                            }
                            ProtectedDataConfig::GnupgAead { .. } => esk_filter(
                                esks,
                                PkeskVersion::V3,
                                &[SkeskVersion::V4, SkeskVersion::V5],
                            ),
                        },
                    };
                    return Ok(Some(Message::Encrypted {
                        esk,
                        edata,
                        is_nested: is_nested > 0,
                    }));
                }
                Tag::Padding => {
                    // drain reader
                    packet.drain()?;
                    packets = crate::packet::PacketParser::new(packet.into_inner());
                }
                Tag::Marker => {
                    // drain reader
                    packet.drain()?;
                    packets = crate::packet::PacketParser::new(packet.into_inner());
                }
                _ => {
                    bail!("unexpected tag in an encrypted message: {:?}", tag);
                }
            }
        }
    }
}

/// Drop PKESK and SKESK with versions that are not aligned with the encryption container
///
/// An implementation processing an Encrypted Message MUST discard any
/// preceding ESK packet with a version that does not align with the
/// version of the payload.
/// See <https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3.2.1-7>
fn esk_filter(
    esk: Vec<Esk>,
    pkesk_allowed: PkeskVersion,
    skesk_allowed: &[SkeskVersion],
) -> Vec<Esk> {
    esk.into_iter()
        .filter(|esk| match esk {
            Esk::PublicKeyEncryptedSessionKey(pkesk) => pkesk.version() == pkesk_allowed,
            Esk::SymKeyEncryptedSessionKey(skesk) => skesk_allowed.contains(&skesk.version()),
        })
        .collect()
}

impl<'a> Message<'a> {
    /// Parse a composed message.
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages>
    fn from_packets(packets: crate::packet::PacketParser<MessageReader<'a>>) -> Result<Self> {
        match MessageParser::new(packets, 0).run()? {
            Some(message) => Ok(message),
            None => {
                bail!("no valid OpenPGP message found");
            }
        }
    }

    /// Parses a message from the given bytes.
    pub fn from_bytes<R: BufRead + std::fmt::Debug + 'a + Send>(source: R) -> Result<Self> {
        let source = MessageReader::Reader(Box::new(source) as Box<dyn DebugBufRead>);
        let parser = crate::packet::PacketParser::new(source);
        Self::from_packets(parser)
    }

    /// Construct a message from the decrypted edata.
    ///
    /// `is_nested` must be passed through from the source `Message`.
    pub(super) fn from_edata(edata: Edata<'a>, is_nested: bool) -> Result<Self> {
        let source = MessageReader::Edata(Box::new(edata));
        Message::internal_from_bytes(source, is_nested)
    }

    /// Construct a message from a compressed data reader.
    ///
    /// `is_nested` must be passed through from the source `Message`.
    pub(super) fn from_compressed(
        reader: CompressedDataReader<MessageReader<'a>>,
        is_nested: bool,
    ) -> Result<Self> {
        let source = MessageReader::Compressed(Box::new(reader));
        Message::internal_from_bytes(source, is_nested)
    }

    fn internal_from_bytes(source: MessageReader<'a>, is_nested: bool) -> Result<Self> {
        let packets = crate::packet::PacketParser::new(source);
        match MessageParser::new(packets, if is_nested { 1 } else { 0 }).run()? {
            Some(message) => Ok(message),
            None => {
                bail!("no valid OpenPGP message found");
            }
        }
    }

    /// From armored file
    pub fn from_armor_file<P: AsRef<Path>>(path: P) -> Result<(Self, crate::armor::Headers)> {
        let file = std::fs::File::open(path)?;
        Self::from_armor(BufReader::new(file))
    }

    /// From armored string
    pub fn from_string(data: &'a str) -> Result<(Self, crate::armor::Headers)> {
        Self::from_armor(data.as_bytes())
    }

    /// From binary file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        Self::from_bytes(BufReader::new(file))
    }

    /// Armored ascii data.
    pub fn from_armor<R: BufRead + std::fmt::Debug + 'a + Send>(
        input: R,
    ) -> Result<(Self, crate::armor::Headers)> {
        Self::from_armor_with_options(input, DearmorOptions::default())
    }

    /// Armored ascii data, with explicit options for dearmoring.
    pub fn from_armor_with_options<R: BufRead + std::fmt::Debug + 'a + Send>(
        input: R,
        opt: DearmorOptions,
    ) -> Result<(Self, crate::armor::Headers)> {
        let mut dearmor = crate::armor::Dearmor::with_options(input, opt);
        dearmor.read_header()?;
        // Safe to unwrap, as read_header succeeded.
        let typ = dearmor
            .typ
            .ok_or_else(|| format_err!("dearmor failed to retrieve armor type"))?;

        match typ {
            // Standard PGP types
            BlockType::File | BlockType::Message | BlockType::MultiPartMessage(_, _) => {
                let headers = dearmor.headers.clone(); // FIXME: avoid clone

                if !Self::matches_block_type(typ) {
                    bail!("unexpected block type: {}", typ);
                }

                Ok((Self::from_bytes(BufReader::new(dearmor))?, headers))
            }
            BlockType::PublicKey
            | BlockType::PrivateKey
            | BlockType::Signature
            | BlockType::CleartextMessage
            | BlockType::PublicKeyPKCS1(_)
            | BlockType::PublicKeyPKCS8
            | BlockType::PublicKeyOpenssh
            | BlockType::PrivateKeyPKCS1(_)
            | BlockType::PrivateKeyPKCS8
            | BlockType::PrivateKeyOpenssh => {
                unimplemented_err!("key format {:?}", typ);
            }
        }
    }

    /// Parse from a reader which might contain ASCII armored data or binary data.
    pub fn from_reader<R: BufRead + std::fmt::Debug + 'a + Send>(
        mut source: R,
    ) -> Result<(Self, Option<crate::armor::Headers>)> {
        if is_binary(&mut source)? {
            let msg = Self::from_bytes(source)?;
            Ok((msg, None))
        } else {
            let (msg, headers) = Self::from_armor(source)?;
            Ok((msg, Some(headers)))
        }
    }

    fn matches_block_type(typ: BlockType) -> bool {
        matches!(
            typ,
            BlockType::Message | BlockType::MultiPartMessage(_, _) | BlockType::File
        )
    }
}
