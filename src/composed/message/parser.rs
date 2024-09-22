use std::iter::Peekable;

use log::debug;

use crate::armor::BlockType;
use crate::composed::message::Message;
use crate::composed::Deserializable;
use crate::errors::{Error, Result};
use crate::packet::Packet;
use crate::types::{PkeskVersion, SkeskVersion, Tag};
use crate::{Edata, Esk};

pub struct MessageParser<I: Sized + Iterator<Item = Result<Packet>>> {
    source: Peekable<I>,
}

fn next<I: Iterator<Item = Result<Packet>>>(packets: &mut Peekable<I>) -> Option<Result<Message>> {
    while let Some(res) = packets.by_ref().next() {
        let packet = match res {
            Ok(packet) => packet,
            Err(err) => return Some(Err(err)),
        };

        debug!("{:?}: ", packet);
        let tag = packet.tag();
        match tag {
            Tag::LiteralData => {
                return match packet.try_into() {
                    Ok(data) => Some(Ok(Message::Literal(data))),
                    Err(err) => Some(Err(err)),
                };
            }
            Tag::CompressedData => {
                return match packet.try_into() {
                    Ok(data) => Some(Ok(Message::Compressed(data))),
                    Err(err) => Some(Err(err)),
                };
            }
            //    ESK :- Public-Key Encrypted Session Key Packet |
            //           Symmetric-Key Encrypted Session Key Packet.
            Tag::PublicKeyEncryptedSessionKey | Tag::SymKeyEncryptedSessionKey => {
                return match packet.try_into() {
                    Ok(p) => {
                        let mut esk: Vec<Esk> = vec![p];

                        // while ESK take em
                        while let Some(res) = packets.next_if(|res| {
                            res.as_ref().is_ok_and(|p| {
                                p.tag() == Tag::PublicKeyEncryptedSessionKey
                                    || p.tag() == Tag::SymKeyEncryptedSessionKey
                            })
                        }) {
                            match res {
                                Ok(packet) => esk.push(packet.try_into().expect("peeked")),
                                Err(e) => return Some(Err(e)),
                            }
                        }

                        // we expect exactly one edata after the ESKs
                        let edata = match packets.next() {
                            Some(Ok(p))
                                if p.tag() == Tag::SymEncryptedData
                                    || p.tag() == Tag::SymEncryptedProtectedData =>
                            {
                                Edata::try_from(p).expect("peeked")
                            }
                            Some(Ok(p)) => {
                                return Some(Err(Error::Message(format!(
                                    "Expected encrypted data packet, but found {:?}",
                                    p
                                ))));
                            }
                            None => {
                                return Some(Err(Error::Message(
                                    "Missing encrypted data packet".to_string(),
                                )))
                            }
                            Some(Err(e)) => return Some(Err(e)),
                        };

                        // Drop PKESK and SKESK with versions that are not aligned with the encryption container
                        fn esk_filter(
                            esk: Vec<Esk>,
                            pkesk_allowed: PkeskVersion,
                            skesk_allowed: SkeskVersion,
                        ) -> Vec<Esk> {
                            esk.into_iter()
                                .filter(|esk| match esk {
                                    Esk::PublicKeyEncryptedSessionKey(pkesk) => {
                                        pkesk.version() == pkesk_allowed
                                    }
                                    Esk::SymKeyEncryptedSessionKey(skesk) => {
                                        skesk.version() == skesk_allowed
                                    }
                                })
                                .collect()
                        }

                        // An implementation processing an Encrypted Message MUST discard any
                        // preceding ESK packet with a version that does not align with the
                        // version of the payload.
                        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3.2.1-7)
                        let esk = match edata {
                            Edata::SymEncryptedData(_) => {
                                esk_filter(esk, PkeskVersion::V3, SkeskVersion::V4)
                            }
                            Edata::SymEncryptedProtectedData(ref p) if p.version() == 1 => {
                                esk_filter(esk, PkeskVersion::V3, SkeskVersion::V4)
                            }
                            Edata::SymEncryptedProtectedData(ref p) if p.version() == 2 => {
                                esk_filter(esk, PkeskVersion::V6, SkeskVersion::V6)
                            }
                            _ => {
                                return Some(Err(format_err!("Unsupported Edata variant")));
                            }
                        };

                        Some(Ok(Message::Encrypted { esk, edata }))
                    }
                    Err(err) => Some(Err(err)),
                };
            }
            Tag::Signature => {
                return match packet.try_into() {
                    Ok(signature) => {
                        let message = match next(packets.by_ref()) {
                            Some(Ok(m)) => Some(Box::new(m)),
                            Some(Err(err)) => return Some(Err(err)),
                            None => None,
                        };

                        Some(Ok(Message::Signed {
                            message,
                            one_pass_signature: None,
                            signature,
                        }))
                    }
                    Err(err) => Some(Err(err)),
                };
            }
            Tag::OnePassSignature => {
                return match packet.try_into() {
                    Ok(p) => {
                        let one_pass_signature = Some(p);

                        let message = match next(packets.by_ref()) {
                            Some(Ok(m)) => Some(Box::new(m)),
                            Some(Err(err)) => return Some(Err(err)),
                            None => None,
                        };

                        let signature = if let Some(res) = packets
                            .next_if(|res| res.as_ref().is_ok_and(|p| p.tag() == Tag::Signature))
                        {
                            match res {
                                Ok(packet) => packet.try_into().expect("peeked"),
                                Err(e) => return Some(Err(e)),
                            }
                        } else {
                            return Some(Err(format_err!(
                                "missing signature for, one pass signature"
                            )));
                        };

                        Some(Ok(Message::Signed {
                            message,
                            one_pass_signature,
                            signature,
                        }))
                    }
                    Err(err) => Some(Err(err)),
                };
            }
            Tag::Marker => {
                // Marker Packets are ignored
                // see https://www.rfc-editor.org/rfc/rfc9580.html#marker-packet
            }
            Tag::Padding => {
                // Padding Packets are ignored
                //
                // "Such a packet MUST be ignored when received."
                // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.14-2)
            }
            _ => {
                return Some(Err(format_err!("unexpected packet {:?}", packet.tag())));
            }
        }
    }

    None
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for MessageParser<I> {
    type Item = Result<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

impl Deserializable for Message {
    /// Parse a composed message.
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages>
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(MessageParser {
            source: packets.peekable(),
        })
    }

    fn matches_block_type(typ: BlockType) -> bool {
        matches!(
            typ,
            BlockType::Message | BlockType::MultiPartMessage(_, _) | BlockType::File
        )
    }
}
