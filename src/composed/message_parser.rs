use std::boxed::Box;
use std::iter::Iterator;

use composed::message::{Message, OnePassSignedMessage};
use composed::Deserializable;
use errors::Result;
use packet::types::{Packet, Tag};

#[derive(Debug)]
enum Group {
    Compressed,
    Literal,
    ESK,
    EncryptedData,
}

impl Deserializable for Message {
    /// Parse a composed message.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-11.3
    fn from_packets<'a>(packets: impl IntoIterator<Item = &'a Packet>) -> Result<Vec<Message>> {
        // stack = [];
        // cur = none;
        // is_esk = false;
        // is_edata =>

        // literal => stack.push new Literal @;
        // compressed compressed => stack.push new Compressed @;
        // signature => cur == OnePassSigned ? close cur @ : stack.push new Signed @;
        // one_pass_signature => stack.push new OnePassSigned @;
        // esk => ensure Encrypted && is_esk = true && cur.esk.push @;
        // edata => ensure Encrypted && is_esk = false && is_edata = true && cur.edata.push @;

        let mut stack: Vec<Message> = Vec::new();
        // track a currently open package
        let mut cur: Option<usize> = None;
        let mut is_esk = false;
        let mut is_edata = false;

        packets.into_iter().for_each(|packet| {
            match packet.tag {
                Tag::Literal => match cur {
                    Some(i) => {
                        if stack[i].is_one_pass_signed() {
                            // setting the message packet if we are currently parsing a one time pass sigend message
                            match stack[i] {
                                Message::Signed {
                                    ref mut one_pass_signed_message,
                                    ..
                                } => {
                                    if let Some(ref mut opsm) = one_pass_signed_message {
                                        opsm.message =
                                            Some(Box::new(Message::Literal(packet.to_owned())));
                                    } else {
                                        panic!("failed one_pass_signed_message setup");
                                    }
                                }
                                _ => panic!("unexpected packet"),
                            }
                        } else {
                            // setting the message on a regular signed message
                            match stack[i] {
                                Message::Signed {
                                    ref mut message, ..
                                } => {
                                    *message = Some(Box::new(Message::Literal(packet.to_owned())));
                                    cur = None;
                                }
                                _ => panic!("unexpected packet"),
                            }
                        }
                    }
                    None => {
                        // just a regular literal message
                        stack.push(Message::Literal(packet.to_owned()));
                    }
                },
                Tag::CompressedData => match cur {
                    Some(i) => if stack[i].is_one_pass_signed() {
                        // setting the message packet if we are currently parsing a one time pass sigend message
                        match stack[i] {
                            Message::Signed {
                                ref mut one_pass_signed_message,
                                ..
                            } => {
                                if let Some(ref mut opsm) = one_pass_signed_message {
                                    opsm.message =
                                        Some(Box::new(Message::Literal(packet.to_owned())));
                                } else {
                                    panic!("failed one_pass_signed_message setup");
                                }
                            }
                            _ => panic!("unexpected packet"),
                        }
                    } else {
                        match stack[i] {
                            Message::Signed {
                                ref mut message, ..
                            } => {
                                *message = Some(Box::new(Message::Compressed(packet.to_owned())));
                                cur = None;
                            }
                            _ => panic!("unexpected packet"),
                        }
                    },
                    None => {
                        stack.push(Message::Compressed(packet.to_owned()));
                    }
                },
                //    ESK :- Public-Key Encrypted Session Key Packet |
                //           Symmetric-Key Encrypted Session Key Packet.
                Tag::PublicKeyEncryptedSessionKey | Tag::SymKeyEncryptedSessionKey => {
                    if is_edata == true {
                        panic!("edata should not be followed by esk");
                    }

                    if cur.is_none() {
                        stack.push(Message::Encrypted {
                            esk: vec![packet.to_owned()],
                            edata: Vec::new(),
                        });
                        cur = Some(stack.len() - 1);
                    }

                    is_esk = true;

                    if let Some(i) = cur {
                        if let Message::Encrypted { ref mut esk, .. } = stack[i] {
                            esk.push(packet.to_owned());
                        } else {
                            panic!("bad esk init");
                        }
                    }
                }
                //    Encrypted Data :- Symmetrically Encrypted Data Packet |
                //          Symmetrically Encrypted Integrity Protected Data Packet
                Tag::SymetricEncryptedData | Tag::SymEncryptedProtectedData => {
                    is_esk = false;
                    is_edata = true;

                    if cur.is_none() {
                        stack.push(Message::Encrypted {
                            esk: Vec::new(),
                            edata: vec![packet.to_owned()],
                        });
                        cur = Some(stack.len() - 1);
                    }

                    if let Some(i) = cur {
                        if let Message::Encrypted { ref mut edata, .. } = stack[i] {
                            edata.push(packet.to_owned());
                        } else {
                            panic!("bad edata init");
                        }
                    }
                }
                Tag::Signature => match cur {
                    Some(i) => {
                        if stack[i].is_one_pass_signed() {
                            match stack[i] {
                                Message::Signed {
                                    ref mut signature, ..
                                } => {
                                    *signature = Some(packet.to_owned());
                                }
                                _ => panic!("unexpected message"),
                            }
                            cur = None;
                        } else {
                            panic!("unexpected signature");
                        }
                    }
                    None => {
                        stack.push(Message::Signed {
                            message: None,
                            one_pass_signed_message: None,
                            signature: Some(packet.to_owned()),
                        });
                        cur = Some(stack.len() - 1);
                    }
                },
                Tag::OnePassSignature => match cur {
                    None => panic!("no standalone one pass signatures allowed"),
                    Some(i) => match stack[i] {
                        Message::Signed {
                            ref mut one_pass_signed_message,
                            ..
                        } => {
                            *one_pass_signed_message = Some(OnePassSignedMessage {
                                one_pass_signature: packet.to_owned(),
                                message: None,
                                signature: None,
                            });
                        }
                        _ => panic!("invalid format"),
                    },
                },
                _ => panic!("unexpected packet {:?}", packet.tag),
            }
        });

        // TODO: assemble final message
        stack.iter().for_each(|s| println!("{:?}", s));

        Ok(stack)
    }
}
