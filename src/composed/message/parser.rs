use std::boxed::Box;
use std::convert::TryInto;
use std::iter::Peekable;

use crate::composed::message::Message;
use crate::composed::Deserializable;
use crate::errors::Result;
use crate::packet::Packet;
use crate::types::Tag;

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
                        let mut esk = vec![p];
                        let mut edata = Vec::new();

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

                        // while edata take em (FIXME: the message grammar only allows one "Encrypted Data" packet)
                        while let Some(res) = packets.next_if(|res| {
                            res.as_ref().is_ok_and(|p| {
                                p.tag() == Tag::SymEncryptedData
                                    || p.tag() == Tag::SymEncryptedProtectedData
                            })
                        }) {
                            match res {
                                Ok(packet) => edata.push(packet.try_into().expect("peeked")),
                                Err(e) => return Some(Err(e)),
                            }
                        }

                        Some(Ok(Message::Encrypted { esk, edata }))
                    }
                    Err(err) => Some(Err(err)),
                };
            }
            //    Encrypted Data :- Symmetrically Encrypted Data Packet |
            //          Symmetrically Encrypted Integrity Protected Data Packet
            Tag::SymEncryptedData | Tag::SymEncryptedProtectedData => {
                return match packet.try_into() {
                    Ok(p) => {
                        let esk = Vec::new();
                        let mut edata = vec![p];

                        // while edata take em (FIXME: the message grammar only allows one "Encrypted Data" packet)
                        while let Some(res) = packets.next_if(|res| {
                            res.as_ref().is_ok_and(|p| {
                                p.tag() == Tag::SymEncryptedData
                                    || p.tag() == Tag::SymEncryptedProtectedData
                            })
                        }) {
                            match res {
                                Ok(packet) => edata.push(packet.try_into().expect("peeked")),
                                Err(e) => return Some(Err(e)),
                            }
                        }

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
                // see https://tools.ietf.org/html/rfc4880#section-5.8
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
    /// Ref: https://tools.ietf.org/html/rfc4880#section-11.3
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(MessageParser {
            source: packets.peekable(),
        })
    }
}
