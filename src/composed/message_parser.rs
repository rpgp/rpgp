use std::boxed::Box;

use composed::message::{Message, OnePassSignature};
use composed::Deserializable;
use errors::Result;
use packet::tags::public_key_encrypted_session_key;
use packet::types::{Packet, Tag};

impl Deserializable for Message {
    /// Parse a composed message.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-11.3
    fn from_packets<'a>(packets: impl IntoIterator<Item = &'a Packet>) -> Result<Vec<Message>> {
        // stack = [];
        // cur = none;
        // is_esk = false;
        // is_edata = false;

        // literal => stack.push new Literal @;
        // compressed compressed => stack.push new Compressed @;
        // signature => cur == OnePassSigned ? close cur @ : stack.push new Signed @;
        // one_pass_signature => stack.push new OnePassSigned @;
        // esk => ensure Encrypted && is_esk = true && cur.esk.push @;
        // edata => ensure Encrypted && is_esk = false && is_edata = true && cur.edata.push @;

        let mut stack: Vec<Message> = Vec::new();
        // track a currently open package
        let mut cur: Option<usize> = None;
        let mut is_edata = false;

        for packet in packets.into_iter() {
            println!(
                "{:?}: tag={} plen={} version={:?}",
                packet.tag,
                packet.tag.clone() as u8,
                packet.body.len(),
                packet.version
            );
            match packet.tag {
                Tag::Literal => match cur {
                    Some(i) => {
                        // setting the message packet if we are currently parsing a sigend message
                        match stack[i] {
                            Message::Signed {
                                ref mut message, ..
                            } => {
                                *message = Some(Box::new(Message::Literal(packet.to_owned())));
                            }
                            _ => panic!("unexpected literal"),
                        }
                    }
                    None => {
                        // just a regular literal message
                        stack.push(Message::Literal(packet.to_owned()));
                    }
                },
                Tag::CompressedData => match cur {
                    Some(i) => {
                        // setting the message packet if we are currently parsing a signed message
                        match stack[i] {
                            Message::Signed {
                                ref mut message, ..
                            } => {
                                *message = Some(Box::new(Message::Literal(packet.to_owned())));
                            }
                            _ => panic!("unexpected packet"),
                        }
                    }
                    None => {
                        // just a regular compressed mesage
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
                            esk: vec![public_key_encrypted_session_key::parse(
                                packet.body.as_slice(),
                            )?],
                            edata: Vec::new(),
                            protected: false,
                        });
                        cur = Some(stack.len() - 1);
                    }

                    if let Some(i) = cur {
                        if let Message::Encrypted { ref mut esk, .. } = stack[i] {
                            esk.push(public_key_encrypted_session_key::parse(
                                packet.body.as_slice(),
                            )?);
                        } else {
                            panic!("bad esk init");
                        }
                    }
                }
                //    Encrypted Data :- Symmetrically Encrypted Data Packet |
                //          Symmetrically Encrypted Integrity Protected Data Packet
                Tag::SymetricEncryptedData | Tag::SymEncryptedProtectedData => {
                    is_edata = true;
                    if cur.is_none() {
                        stack.push(Message::Encrypted {
                            esk: Vec::new(),
                            edata: vec![packet.to_owned()],
                            protected: packet.tag == Tag::SymEncryptedProtectedData,
                        });
                        cur = Some(stack.len() - 1);
                    }

                    if let Some(i) = cur {
                        let mut el = stack.pop().unwrap();
                        stack.push(update_message(el, packet));
                    }
                }
                Tag::Signature => match cur {
                    Some(i) => match stack[i] {
                        Message::Signed {
                            ref mut signature, ..
                        } => {
                            *signature = Some(packet.to_owned());
                            cur = None;
                        }
                        _ => panic!("unexpected signature"),
                    },
                    None => {
                        stack.push(Message::Signed {
                            message: None,
                            one_pass_signature: None,
                            signature: Some(packet.to_owned()),
                        });
                    }
                },
                Tag::OnePassSignature => {
                    stack.push(Message::Signed {
                        message: None,
                        one_pass_signature: Some(OnePassSignature(packet.to_owned())),
                        signature: None,
                    });
                    cur = Some(stack.len() - 1);
                }
                _ => panic!("unexpected packet {:?}", packet.tag),
            }
        }

        Ok(stack)
    }
}

fn update_message(mut el: Message, packet: &Packet) -> Message {
    match el {
        Message::Encrypted { .. } => update_encrypted(el, packet),
        Message::Signed { .. } => update_signed(el, packet),
        _ => panic!("bad edata init"),
    }
}
fn update_encrypted(mut el: Message, packet: &Packet) -> Message {
    if let Message::Encrypted {
        ref mut edata,
        ref mut protected,
        ..
    } = el
    {
        edata.push(packet.to_owned());
        *protected = packet.tag == Tag::SymEncryptedProtectedData;
    }

    el
}

fn update_signed(mut el: Message, packet: &Packet) -> Message {
    if let Message::Signed {
        message,
        signature,
        one_pass_signature,
    } = el
    {
        let new_message = match message {
            Some(msg) => {
                if let Message::Encrypted { .. } = *msg {
                    Some(Box::new(update_encrypted((*msg).clone(), packet)))
                } else {
                    panic!("bad edata init in signed message");
                }
            }
            None => Some(Box::new(Message::Encrypted {
                esk: Vec::new(),
                edata: vec![packet.to_owned()],
                protected: packet.tag == Tag::SymEncryptedProtectedData,
            })),
        };

        Message::Signed {
            message: new_message,
            signature,
            one_pass_signature,
        }
    } else {
        unreachable!()
    }
}
