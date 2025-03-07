use std::io::{self, BufRead, Read};

use bytes::{Buf, Bytes};
use log::{debug, warn};

use crate::armor;
use crate::composed::message::decrypt::*;
use crate::composed::signed_key::SignedSecretKey;
use crate::errors::{Error, Result};
use crate::packet::{
    LiteralDataHeader, OnePassSignature, Packet, PacketHeader, PacketTrait,
    PublicKeyEncryptedSessionKey, Signature, SymEncryptedProtectedDataConfig,
    SymKeyEncryptedSessionKey,
};
use crate::parsing_reader::BufReadParsing;
use crate::ser::Serialize;
use crate::types::{EskType, Fingerprint, KeyDetails, Password, PkeskVersion, PublicKeyTrait, Tag};

use super::reader::{
    CompressedDataReader, LiteralDataReader, PacketBodyReader, SignatureBodyReader,
    SignatureOnePassReader, SymEncryptedDataReader, SymEncryptedProtectedDataReader,
};

/// An [OpenPGP message](https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages)
/// Encrypted Message | Signed Message | Compressed Message | Literal Message.
#[derive(Debug)]
pub enum Message<'a> {
    /// Literal Message: Literal Data Packet.
    Literal {
        reader: LiteralDataReader<Box<dyn BufRead + 'a>>,
    },
    /// Compressed Message: Compressed Data Packet.
    Compressed {
        reader: CompressedDataReader<Box<dyn BufRead + 'a>>,
    },
    /// Signed Message: Signature Packet, OpenPGP Message
    Signed {
        /// The actual signature
        signature: Signature,
        reader: SignatureBodyReader<'a>,
    },
    /// One-Pass Signed Message: One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
    SignedOnePass {
        /// for signature packets that contain a one pass message
        one_pass_signature: OnePassSignature,
        reader: SignatureOnePassReader<'a>,
    },
    /// Encrypted Message: Encrypted Data | ESK Sequence, Encrypted Data.
    Encrypted {
        /// ESK Sequence: ESK | ESK Sequence, ESK.
        esk: Vec<Esk>,
        edata: Edata<'a>,
    },
}

pub(crate) enum MessageParts {
    Literal {
        packet_header: PacketHeader,
        header: LiteralDataHeader,
    },
    Compressed {
        packet_header: PacketHeader,
    },
    Signed {
        signature: Signature,
        hash: Box<[u8]>,
        parts: Box<MessageParts>,
    },
    SignedOnePass {
        one_pass_signature: OnePassSignature,
        hash: Box<[u8]>,
        signature: Signature,
        parts: Box<MessageParts>,
    },
    Encrypted {
        packet_header: PacketHeader,
        esk: Vec<Esk>,
        config: Option<SymEncryptedProtectedDataConfig>,
    },
}

impl<'a> Message<'a> {
    pub(crate) fn into_parts(self) -> (Box<dyn BufRead + 'a>, MessageParts) {
        match self {
            Message::Literal { reader } => {
                assert!(reader.is_done());
                let packet_header = reader.packet_header();
                let header = reader.data_header().unwrap().clone();
                (
                    reader.into_inner().into_inner(),
                    MessageParts::Literal {
                        packet_header,
                        header,
                    },
                )
            }
            Message::Compressed { reader } => {
                assert!(reader.is_done());
                let packet_header = reader.packet_header();
                (
                    reader.into_inner().into_inner(),
                    MessageParts::Compressed { packet_header },
                )
            }
            Message::Signed { signature, reader } => {
                assert!(reader.is_done());
                let SignatureBodyReader::Done { hash, source } = reader else {
                    panic!("invalid state");
                };
                let (reader, parts) = source.into_parts();
                (
                    reader,
                    MessageParts::Signed {
                        signature,
                        hash,
                        parts: Box::new(parts),
                    },
                )
            }
            Message::SignedOnePass {
                one_pass_signature,
                reader,
            } => {
                let SignatureOnePassReader::Done {
                    hash,
                    source,
                    signature,
                } = reader
                else {
                    panic!("invalid state");
                };

                let (reader, parts) = source.into_parts();
                (
                    reader,
                    MessageParts::SignedOnePass {
                        one_pass_signature,
                        hash,
                        signature,
                        parts: Box::new(parts),
                    },
                )
            }
            Message::Encrypted { esk, edata } => match edata {
                Edata::SymEncryptedData { reader } => {
                    let packet_header = reader.packet_header();
                    assert!(reader.is_done());
                    (
                        reader.into_inner().into_inner(),
                        MessageParts::Encrypted {
                            packet_header,
                            esk,
                            config: None,
                        },
                    )
                }
                Edata::SymEncryptedProtectedData { reader } => {
                    assert!(reader.is_done());
                    let packet_header = reader.packet_header();
                    let config = Some(reader.config().clone());
                    (
                        reader.into_inner().into_inner(),
                        MessageParts::Encrypted {
                            packet_header,
                            esk,
                            config,
                        },
                    )
                }
            },
        }
    }
}

impl MessageParts {
    pub(crate) fn into_message<'a>(self, reader: Box<dyn BufRead + 'a>) -> Message<'a> {
        match self {
            MessageParts::Literal {
                packet_header,
                header,
            } => Message::Literal {
                reader: LiteralDataReader::new_done(
                    PacketBodyReader::new_done(packet_header, reader),
                    header,
                ),
            },
            MessageParts::Compressed { packet_header } => Message::Compressed {
                reader: CompressedDataReader::new_done(PacketBodyReader::new_done(
                    packet_header,
                    reader,
                )),
            },
            MessageParts::Signed {
                signature,
                parts,
                hash,
            } => {
                let source = parts.into_message(reader);
                Message::Signed {
                    signature,
                    reader: SignatureBodyReader::Done {
                        source: Box::new(source),
                        hash,
                    },
                }
            }
            MessageParts::SignedOnePass {
                one_pass_signature,
                hash,
                signature,
                parts,
            } => {
                let source = parts.into_message(reader);
                Message::SignedOnePass {
                    one_pass_signature,
                    reader: SignatureOnePassReader::Done {
                        hash,
                        source: Box::new(source),
                        signature,
                    },
                }
            }
            MessageParts::Encrypted {
                packet_header,
                esk,
                config,
            } => {
                let reader = PacketBodyReader::new_done(packet_header, reader);
                let edata = if let Some(config) = config {
                    let reader = SymEncryptedProtectedDataReader::new_done(config, reader);
                    Edata::SymEncryptedProtectedData { reader }
                } else {
                    let reader = SymEncryptedDataReader::new_done(reader);
                    Edata::SymEncryptedData { reader }
                };
                Message::Encrypted { esk, edata }
            }
        }
    }
}

/// Encrypted Session Key
///
/// Public-Key Encrypted Session Key Packet |
/// Symmetric-Key Encrypted Session Key Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esk {
    PublicKeyEncryptedSessionKey(PublicKeyEncryptedSessionKey),
    SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey),
}

impl Esk {
    pub fn try_from_reader<'a>(
        packet: &mut PacketBodyReader<Box<dyn BufRead + 'a>>,
    ) -> Result<Self> {
        let packet_header = packet.packet_header();
        match packet_header.tag() {
            Tag::PublicKeyEncryptedSessionKey => {
                let esk = PublicKeyEncryptedSessionKey::try_from_reader(packet_header, packet)?;
                Ok(Self::PublicKeyEncryptedSessionKey(esk))
            }
            Tag::SymKeyEncryptedSessionKey => {
                let esk = SymKeyEncryptedSessionKey::try_from_reader(packet_header, packet)?;
                Ok(Self::SymKeyEncryptedSessionKey(esk))
            }
            _ => unreachable!("must not called with other tags"),
        }
    }
}

impl_try_from_into!(
    Esk,
    PublicKeyEncryptedSessionKey => PublicKeyEncryptedSessionKey,
    SymKeyEncryptedSessionKey => SymKeyEncryptedSessionKey
);

impl Esk {
    pub fn tag(&self) -> Tag {
        match self {
            Esk::PublicKeyEncryptedSessionKey(_) => Tag::PublicKeyEncryptedSessionKey,
            Esk::SymKeyEncryptedSessionKey(_) => Tag::SymKeyEncryptedSessionKey,
        }
    }
}

impl TryFrom<Packet> for Esk {
    type Error = Error;

    fn try_from(other: Packet) -> Result<Esk> {
        match other {
            Packet::PublicKeyEncryptedSessionKey(k) => Ok(Esk::PublicKeyEncryptedSessionKey(k)),
            Packet::SymKeyEncryptedSessionKey(k) => Ok(Esk::SymKeyEncryptedSessionKey(k)),
            _ => Err(format_err!("not a valid edata packet: {:?}", other)),
        }
    }
}

impl From<Esk> for Packet {
    fn from(other: Esk) -> Packet {
        match other {
            Esk::PublicKeyEncryptedSessionKey(k) => Packet::PublicKeyEncryptedSessionKey(k),
            Esk::SymKeyEncryptedSessionKey(k) => Packet::SymKeyEncryptedSessionKey(k),
        }
    }
}

impl Serialize for Esk {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.to_writer_with_header(writer),
            Esk::SymKeyEncryptedSessionKey(k) => k.to_writer_with_header(writer),
        }
    }

    fn write_len(&self) -> usize {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.write_len_with_header(),
            Esk::SymKeyEncryptedSessionKey(k) => k.write_len_with_header(),
        }
    }
}

/// Encrypted Data:
/// Symmetrically Encrypted Data Packet |
/// Symmetrically Encrypted Integrity Protected Data Packet
#[derive(Debug)]
pub enum Edata<'a> {
    SymEncryptedData {
        reader: SymEncryptedDataReader<Box<dyn BufRead + 'a>>,
    },
    SymEncryptedProtectedData {
        reader: SymEncryptedProtectedDataReader<Box<dyn BufRead + 'a>>,
    },
}

impl<'a> Edata<'a> {
    pub fn try_from_reader(reader: PacketBodyReader<Box<dyn BufRead + 'a>>) -> Result<Self> {
        match reader.packet_header().tag() {
            Tag::SymEncryptedData => {
                let reader = SymEncryptedDataReader::new(reader)?;
                Ok(Self::SymEncryptedData { reader })
            }
            Tag::SymEncryptedProtectedData => {
                let reader = SymEncryptedProtectedDataReader::new(reader)?;
                Ok(Self::SymEncryptedProtectedData { reader })
            }
            _ => unreachable!("must not be called with a different tag"),
        }
    }
}

impl BufRead for Edata<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::SymEncryptedData { reader } => reader.fill_buf(),
            Self::SymEncryptedProtectedData { reader } => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::SymEncryptedData { reader } => reader.consume(amt),
            Self::SymEncryptedProtectedData { reader } => reader.consume(amt),
        }
    }
}

impl Read for Edata<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::SymEncryptedData { reader } => reader.read(buf),
            Self::SymEncryptedProtectedData { reader } => reader.read(buf),
        }
    }
}

impl<'a> Edata<'a> {
    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::SymEncryptedData { reader } => reader.packet_header(),
            Self::SymEncryptedProtectedData { reader } => reader.packet_header(),
        }
    }

    pub fn tag(&self) -> Tag {
        self.packet_header().tag()
    }

    /// Transform decrypted data into a message.
    /// Bails if the packets contain no message or multiple messages.
    fn process_decrypted(packet_data: Bytes) -> Result<Message<'static>> {
        let message = Message::from_bytes(packet_data.reader())?;

        Ok(message)
    }

    pub fn decrypt(self, key: PlainSessionKey) -> Result<Message<'a>> {
        todo!()
        // let protected = self.tag() == Tag::SymEncryptedProtectedData;
        // debug!("decrypting protected = {:?}", protected);

        // match key {
        //     PlainSessionKey::V3_4 { sym_alg, ref key } => {
        //         ensure!(
        //             sym_alg != SymmetricKeyAlgorithm::Plaintext,
        //             "session key algorithm cannot be plaintext"
        //         );

        //         match self {
        //             Self::SymEncryptedProtectedData(p) => {
        //                 ensure_eq!(
        //                     self.version(),
        //                     Some(1),
        //                     "Version mismatch between key and integrity packet"
        //                 );
        //                 let data = p.decrypt(key, Some(sym_alg))?;
        //                 Self::process_decrypted(data.into())
        //             }
        //             Self::SymEncryptedData(p) => {
        //                 ensure_eq!(
        //                     self.version(),
        //                     None,
        //                     "Version mismatch between key and integrity packet"
        //                 );
        //                 let mut prefix = BytesMut::from(p.data());
        //                 let mut data = prefix.split_off(sym_alg.cfb_prefix_size());
        //                 sym_alg.decrypt(key, &mut prefix, &mut data)?;
        //                 Self::process_decrypted(data.freeze())
        //             }
        //         }
        //     }
        //     PlainSessionKey::V5 { .. } => match self {
        //         Self::SymEncryptedProtectedData(_p) => {
        //             ensure_eq!(
        //                 self.version(),
        //                 Some(2),
        //                 "Version mismatch between key and integrity packet"
        //             );
        //             unimplemented_err!("V5 decryption");
        //         }
        //         Self::SymEncryptedData(_) => {
        //             bail!("invalid packet combination");
        //         }
        //     },
        //     PlainSessionKey::V6 { ref key } => match self {
        //         Self::SymEncryptedProtectedData(p) => {
        //             ensure_eq!(
        //                 self.version(),
        //                 Some(2),
        //                 "Version mismatch between key and integrity packet"
        //             );

        //             let decrypted_packets = p.decrypt(key, None)?;
        //             Self::process_decrypted(decrypted_packets.into())
        //         }
        //         Self::SymEncryptedData(_) => {
        //             bail!("invalid packet combination");
        //         }
        //     },
        // }
    }
}

/// The result of signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// This signature was found to be valid against the key.
    Valid(Signature),
    /// The signature was invalid
    Invalid,
}

impl<'a> Message<'a> {
    /// Decompresses the data if compressed.
    pub fn decompress(self) -> Result<Self> {
        match self {
            Message::Compressed { reader } => Message::from_bytes(reader.decompress()?),
            Message::Signed { signature, reader } => Ok(Message::Signed {
                signature,
                reader: reader.decompress()?,
            }),
            Message::SignedOnePass {
                one_pass_signature,
                reader,
            } => Ok(Message::SignedOnePass {
                one_pass_signature,
                reader: reader.decompress()?,
            }),
            Message::Encrypted { .. } => Ok(self),
            Message::Literal { .. } => Ok(self),
        }
    }

    /// Recursively find all signatures found in this message and attempt to verify
    /// them against the passed in keys.
    ///
    /// Only signed and one pass signed messages can be verified.
    /// The message must have been read to the end before calling this.
    ///
    /// The current recursion limit is `1024`.
    pub fn verify_nested(&self, keys: &[&dyn PublicKeyTrait]) -> Result<Vec<VerificationResult>> {
        let mut out = vec![VerificationResult::Invalid; keys.len()];

        let mut current_message = self;
        // do not recurse arbitrarily deep
        for _ in 0..1024 {
            match current_message {
                Message::SignedOnePass { reader, .. } => {
                    for (key, res) in keys.iter().zip(out.iter_mut()) {
                        match current_message.verify(*key) {
                            Ok(sig) => {
                                *res = VerificationResult::Valid(sig.clone());
                            }
                            Err(_err) => {
                                // no match
                            }
                        }
                    }

                    current_message = reader.get_ref();
                }
                Message::Signed { reader, .. } => {
                    for (key, res) in keys.iter().zip(out.iter_mut()) {
                        match current_message.verify(*key) {
                            Ok(sig) => {
                                *res = VerificationResult::Valid(sig.clone());
                            }
                            Err(_err) => {
                                // no match
                            }
                        }
                    }

                    current_message = reader.get_ref();
                }
                Message::Literal { .. } => {
                    break;
                }
                Message::Compressed { .. } => {
                    bail!("message must be decompressed before verifying");
                }
                Message::Encrypted { .. } => {
                    bail!("message must be decrypted before verifying");
                }
            }
        }

        Ok(out)
    }

    /// Reads the contents and discards it, then verifies the message.
    pub fn verify_read(&mut self, key: &dyn PublicKeyTrait) -> Result<&Signature> {
        self.drain()?;
        let sig = self.verify(key)?;
        Ok(sig)
    }

    /// Verify this message.
    ///
    /// Only signed and one pass signed messages can be verified.
    /// The message must have been read to the end before calling this.
    ///
    /// If the signature is valid, returns the matching signature.
    pub fn verify(&self, key: &dyn PublicKeyTrait) -> Result<&Signature> {
        match self {
            Message::SignedOnePass { reader, .. } => {
                let Some(calculated_hash) = reader.hash() else {
                    bail!("cannot verify message before reading it to the end");
                };
                let Some(signature) = reader.signature() else {
                    bail!("cannot verify message before reading the final signature packet");
                };

                // Check that the high 16 bits of the hash from the signature packet match with the hash we
                // just calculated.
                //
                // "When verifying a version 6 signature, an implementation MUST reject the signature if
                // these octets do not match the first two octets of the computed hash."
                //
                // (See https://www.rfc-editor.org/rfc/rfc9580.html#name-notes-on-signatures)
                //
                // (Note: we currently also reject v4 signatures if the calculated hash doesn't match the
                // high 16 bits in the signature packet, even though RFC 9580 doesn't strictly require this)
                ensure_eq!(
                    &signature.signed_hash_value,
                    &calculated_hash[0..2],
                    "signature: invalid signed hash value"
                );
                key.verify_signature(
                    signature.config.hash_alg,
                    calculated_hash,
                    &signature.signature,
                )?;
                Ok(signature)
            }
            Message::Signed {
                signature, reader, ..
            } => {
                let Some(calculated_hash) = reader.hash() else {
                    bail!("cannot verify message before reading it to the end");
                };

                // Check that the high 16 bits of the hash from the signature packet match with the hash we
                // just calculated.
                //
                // "When verifying a version 6 signature, an implementation MUST reject the signature if
                // these octets do not match the first two octets of the computed hash."
                //
                // (See https://www.rfc-editor.org/rfc/rfc9580.html#name-notes-on-signatures)
                //
                // (Note: we currently also reject v4 signatures if the calculated hash doesn't match the
                // high 16 bits in the signature packet, even though RFC 9580 doesn't strictly require this)
                ensure_eq!(
                    &signature.signed_hash_value,
                    &calculated_hash[0..2],
                    "signature: invalid signed hash value"
                );
                key.verify_signature(
                    signature.config.hash_alg,
                    calculated_hash,
                    &signature.signature,
                )?;

                Ok(signature)
            }
            Message::Compressed { .. } => {
                bail!("message must be decompressed before verifying");
            }
            Message::Encrypted { .. } => {
                bail!("message must be decrypted before verifying");
            }
            Message::Literal { .. } => {
                bail!("message was not signed");
            }
        }
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt(
        self,
        key_pws: &[Password],
        keys: &[&SignedSecretKey],
    ) -> Result<(Message<'a>, Vec<Fingerprint>)> {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("not encrypted");
            }
            Message::Signed { reader, signature } => {
                let (reader, fps) = reader.decrypt(key_pws, keys)?;
                Ok((Message::Signed { signature, reader }, fps))
            }
            Message::SignedOnePass {
                reader,
                one_pass_signature,
            } => {
                let (reader, fps) = reader.decrypt(key_pws, keys)?;
                Ok((
                    Message::SignedOnePass {
                        one_pass_signature,
                        reader,
                    },
                    fps,
                ))
            }
            Message::Encrypted { esk, edata, .. } => {
                let valid_keys =
                    keys.iter()
                        .zip(key_pws.iter())
                        .filter_map(|(key, key_pw)| {
                            // search for a packet with a key id that we have and that key.
                            let mut packet = None;
                            let mut encoding_key = None;
                            let mut encoding_subkey = None;

                            for esk_packet in esk.iter().filter_map(|k| match k {
                                Esk::PublicKeyEncryptedSessionKey(k) => Some(k),
                                _ => None,
                            }) {
                                debug!("esk packet: {:?}", esk_packet);
                                debug!("{:?}", key.key_id());
                                debug!(
                                    "{:?}",
                                    key.secret_subkeys
                                        .iter()
                                        .map(|k| k.key_id())
                                        .collect::<Vec<_>>()
                                );

                                // find the matching key or subkey

                                if esk_packet.match_identity(&key.primary_key.public_key()) {
                                    encoding_key = Some(&key.primary_key);
                                }

                                if encoding_key.is_none() {
                                    encoding_subkey = key.secret_subkeys.iter().find(|subkey| {
                                        esk_packet.match_identity(&subkey.public_key())
                                    });
                                }

                                if encoding_key.is_some() || encoding_subkey.is_some() {
                                    packet = Some(esk_packet);
                                    break;
                                }
                            }

                            packet.map(|packet| (packet, encoding_key, encoding_subkey, key_pw))
                        })
                        .collect::<Vec<_>>();

                if valid_keys.is_empty() {
                    return Err(Error::MissingKey);
                }

                let session_keys = valid_keys
                    .iter()
                    .map(|(pkesk, encoding_key, encoding_subkey, key_pw)| {
                        let typ = match pkesk.version() {
                            PkeskVersion::V3 => EskType::V3_4,
                            PkeskVersion::V6 => EskType::V6,
                            PkeskVersion::Other(v) => {
                                unimplemented_err!("Unexpected PKESK version {}", v)
                            }
                        };

                        if let Some(ek) = encoding_key {
                            debug!("decrypt session key");

                            let values = pkesk.values()?;
                            let session_key = ek.unlock(key_pw, |pub_params, priv_key| {
                                priv_key.decrypt(pub_params, values, typ, &ek.public_key())
                            })?;
                            Ok((ek.fingerprint(), session_key))
                        } else if let Some(ek) = encoding_subkey {
                            let values = pkesk.values()?;
                            let session_key = ek.unlock(key_pw, |pub_params, priv_key| {
                                priv_key.decrypt(pub_params, values, typ, &ek.public_key())
                            })?;
                            Ok((ek.fingerprint(), session_key))
                        } else {
                            unreachable!("either a key or a subkey were found");
                        }
                    })
                    .filter(|res| match res {
                        Ok(_) => true,
                        Err(err) => {
                            warn!("failed to decrypt session_key for key: {:?}", err);
                            false
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;

                ensure!(!session_keys.is_empty(), "failed to decrypt session key");

                // make sure all the keys are the same, otherwise we are in a bad place
                let session_key = {
                    let (_key_id, k0) = &session_keys[0];
                    if !session_keys.iter().skip(1).all(|(_, k)| k0 == k) {
                        bail!("found inconsistent session keys, possible message corruption");
                    }

                    // TODO: avoid cloning
                    k0.clone()
                };

                let ids = session_keys.into_iter().map(|(k, _)| k).collect();
                let msg = edata.decrypt(session_key)?;

                Ok((msg, ids))
            }
        }
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt_with_password(self, msg_pw: &Password) -> Result<Message<'a>> {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("message is not encrypted");
            }
            Message::Signed { reader, signature } => {
                let reader = reader.decrypt_with_password(msg_pw)?;
                Ok(Message::Signed { reader, signature })
            }
            Message::SignedOnePass {
                reader,
                one_pass_signature,
            } => {
                let reader = reader.decrypt_with_password(msg_pw)?;
                Ok(Message::SignedOnePass {
                    reader,
                    one_pass_signature,
                })
            }
            Message::Encrypted { esk, edata, .. } => {
                // TODO: handle multiple passwords
                let skesk = esk.into_iter().find_map(|esk| match esk {
                    Esk::SymKeyEncryptedSessionKey(k) => Some(k),
                    _ => None,
                });

                ensure!(skesk.is_some(), "message is not password protected");

                let session_key =
                    decrypt_session_key_with_password(&skesk.expect("checked above"), msg_pw)?;
                edata.decrypt(session_key)
            }
        }
    }

    pub fn decrypt_with_session_key(self, session_key: PlainSessionKey) -> Result<Message<'a>> {
        todo!()
    }

    /// Check if this message is a signature, that was signed with a one pass signature.
    pub fn is_one_pass_signed(&self) -> bool {
        matches!(self, Message::SignedOnePass { .. })
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Message::Encrypted { .. })
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, Message::SignedOnePass { .. } | Message::Signed { .. })
    }

    /// Is this a compressed message?
    pub fn is_compressed(&self) -> bool {
        matches!(self, Message::Compressed { .. })
    }

    pub fn is_literal(&self) -> bool {
        match self {
            Message::Literal { .. } => true,
            _ => false,
        }
    }

    /// If this is a literal message, returns the literal data header
    pub fn literal_data_header(&self) -> Option<&LiteralDataHeader> {
        match self {
            Self::Literal { reader } => reader.data_header(),
            Self::Compressed { .. } => None,
            Self::Signed { reader, .. } => reader.get_ref().literal_data_header(),
            Self::SignedOnePass { reader, .. } => reader.get_ref().literal_data_header(),
            Self::Encrypted { .. } => None,
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Literal { reader } => reader.packet_header(),
            Self::Compressed { reader } => reader.packet_header(),
            Self::Signed { reader, .. } => reader.get_ref().packet_header(),
            Self::SignedOnePass { reader, .. } => reader.get_ref().packet_header(),
            Self::Encrypted { edata, .. } => edata.packet_header(),
        }
    }

    /// Consumes the reader and reads into a vec.
    pub fn as_data_vec(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Consumes the reader and reads into a string.
    pub fn as_data_string(&mut self) -> io::Result<String> {
        let mut out = String::new();
        self.read_to_string(&mut out)?;
        Ok(out)
    }

    pub fn into_inner(self) -> PacketBodyReader<Box<dyn BufRead + 'a>> {
        match self {
            Self::Literal { reader } => reader.into_inner(),
            Self::Compressed { reader } => reader.into_inner(),
            Self::Signed { reader, .. } => reader.into_inner(),
            Self::SignedOnePass { reader, .. } => reader.into_inner(),
            Self::Encrypted { edata, .. } => match edata {
                Edata::SymEncryptedData { reader } => reader.into_inner(),
                Edata::SymEncryptedProtectedData { reader } => reader.into_inner(),
            },
        }
    }
}

impl Read for Message<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Literal { reader } => reader.read(buf),
            Self::Compressed { reader } => reader.read(buf),
            Self::Signed { reader, .. } => reader.read(buf),
            Self::SignedOnePass { reader, .. } => reader.read(buf),
            Self::Encrypted { edata, .. } => edata.read(buf),
        }
    }
}

impl BufRead for Message<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Literal { reader } => reader.fill_buf(),
            Self::Compressed { reader } => reader.fill_buf(),
            Self::Signed { reader, .. } => reader.fill_buf(),
            Self::SignedOnePass { reader, .. } => reader.fill_buf(),
            Self::Encrypted { edata, .. } => edata.fill_buf(),
        }
    }
    fn consume(&mut self, amt: usize) {
        match self {
            Self::Literal { reader } => reader.consume(amt),
            Self::Compressed { reader } => reader.consume(amt),
            Self::Signed { reader, .. } => reader.consume(amt),
            Self::SignedOnePass { reader, .. } => reader.consume(amt),
            Self::Encrypted { edata, .. } => edata.consume(amt),
        }
    }
}

/// Options for generating armored content.
#[derive(Debug, Clone)]
pub struct ArmorOptions<'a> {
    /// Armor headers
    pub headers: Option<&'a armor::Headers>,
    /// Should a checksum be included? Default to `true`.
    pub include_checksum: bool,
}

impl Default for ArmorOptions<'_> {
    fn default() -> Self {
        Self {
            headers: None,
            include_checksum: true,
        }
    }
}

impl<'a> From<Option<&'a armor::Headers>> for ArmorOptions<'a> {
    fn from(headers: Option<&'a armor::Headers>) -> Self {
        Self {
            headers,
            include_checksum: true,
        }
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::unwrap_used)]

//     use std::fs;

//     use rand::SeedableRng;
//     use rand_chacha::ChaCha8Rng;

//     use super::super::Builder;
//     use super::*;
//     use crate::cleartext::CleartextSignedMessage;
//     use crate::SignedPublicKey;

//     #[test]
//     fn test_compression_zlib() {
//         let lit_msg = Builder::new_literal("hello-zlib.txt", "hello world").unwrap();

//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
//         let uncompressed_msg = compressed_msg.decompress().unwrap();

//         assert_eq!(&lit_msg, &uncompressed_msg);
//     }

//     #[test]
//     fn test_compression_zip() {
//         let lit_msg = Message::new_literal("hello-zip.txt", "hello world").unwrap();

//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZIP).unwrap();
//         let uncompressed_msg = compressed_msg.decompress().unwrap();

//         assert_eq!(&lit_msg, &uncompressed_msg);
//     }

//     #[test]
//     #[cfg(feature = "bzip2")]
//     fn test_compression_bzip2() {
//         let lit_msg = Message::new_literal("hello-zip.txt", "hello world").unwrap();

//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::BZip2).unwrap();
//         let uncompressed_msg = compressed_msg.decompress().unwrap();

//         assert_eq!(&lit_msg, &uncompressed_msg);
//     }

//     #[test]
//     fn test_compression_uncompressed() {
//         let lit_msg = Message::new_literal("hello.txt", "hello world").unwrap();

//         let compressed_msg = lit_msg
//             .compress(CompressionAlgorithm::Uncompressed)
//             .unwrap();
//         let uncompressed_msg = compressed_msg.decompress().unwrap();

//         assert_eq!(&lit_msg, &uncompressed_msg);
//     }

//     #[test]
//     fn test_rsa_encryption_seipdv1() {
//         let _ = pretty_env_logger::try_init();

//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
//                 .unwrap(),
//         )
//         .unwrap();

//         // subkey[0] is the encryption key
//         let pkey = skey.secret_subkeys[0].public_key();
//         let mut rng = rand::rngs::StdRng::seed_from_u64(100);
//         let mut rng2 = rand::rngs::StdRng::seed_from_u64(100);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

//         // Encrypt and test that rng is the only source of randomness.
//         let encrypted = compressed_msg
//             .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
//             .unwrap();
//         let encrypted2 = compressed_msg
//             .encrypt_to_keys_seipdv1(&mut rng2, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
//             .unwrap();
//         assert_eq!(encrypted, encrypted2);

//         let armored = encrypted.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-rsa.asc", &armored).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

//         let decrypted = parsed.decrypt(&["test".into()], &[&skey]).unwrap().0;

//         assert_eq!(compressed_msg, decrypted);
//     }

//     #[test]
//     fn test_rsa_encryption_seipdv2() {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
//                 .unwrap(),
//         )
//         .unwrap();

//         // subkey[0] is the encryption key
//         let pkey = skey.secret_subkeys[0].public_key();
//         let mut rng = rand::rngs::StdRng::seed_from_u64(100);
//         let mut rng2 = rand::rngs::StdRng::seed_from_u64(100);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

//         // Encrypt and test that rng is the only source of randomness.
//         let encrypted = compressed_msg
//             .encrypt_to_keys_seipdv2(
//                 &mut rng,
//                 SymmetricKeyAlgorithm::AES128,
//                 AeadAlgorithm::Ocb,
//                 ChunkSize::default(),
//                 &[&pkey][..],
//             )
//             .unwrap();
//         let encrypted2 = compressed_msg
//             .encrypt_to_keys_seipdv2(
//                 &mut rng2,
//                 SymmetricKeyAlgorithm::AES128,
//                 AeadAlgorithm::Ocb,
//                 ChunkSize::default(),
//                 &[&pkey][..],
//             )
//             .unwrap();
//         assert_eq!(encrypted, encrypted2);

//         let armored = encrypted.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-rsa.asc", &armored).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

//         let decrypted = parsed.decrypt(&["test".into()], &[&skey]).unwrap().0;

//         assert_eq!(compressed_msg, decrypted);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv1() {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();

//         // subkey[0] is the encryption key
//         let pkey = skey.secret_subkeys[0].public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
//         for _ in 0..1000 {
//             let encrypted = compressed_msg
//                 .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
//                 .unwrap();

//             let armored = encrypted.to_armored_bytes(None.into()).unwrap();
//             // fs::write("./message-x25519.asc", &armored).unwrap();

//             let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

//             let decrypted = parsed.decrypt(&["".into()], &[&skey]).unwrap().0;

//             assert_eq!(compressed_msg, decrypted);
//         }
//     }

//     fn x25519_encryption_seipdv2(aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();

//         // subkey[0] is the encryption key
//         let pkey = skey.secret_subkeys[0].public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

//         for _ in 0..1000 {
//             let encrypted = compressed_msg
//                 .encrypt_to_keys_seipdv2(&mut rng, sym, aead, ChunkSize::default(), &[&pkey][..])
//                 .unwrap();

//             let armored = encrypted.to_armored_bytes(None.into()).unwrap();
//             // fs::write("./message-x25519.asc", &armored).unwrap();

//             let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

//             let decrypted = parsed.decrypt(&["".into()], &[&skey]).unwrap().0;

//             assert_eq!(compressed_msg, decrypted);
//         }
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_ocb_aes128() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_eax_aes128() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_gcm_aes128() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_ocb_aes192() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_eax_aes192() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_gcm_aes192() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_ocb_aes256() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_eax_aes256() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_x25519_encryption_seipdv2_gcm_aes256() {
//         x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_password_encryption_seipdv1() {
//         let _ = pretty_env_logger::try_init();

//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

//         let s2k = StringToKey::new_default(&mut rng);

//         let encrypted = compressed_msg
//             .encrypt_with_password_seipdv1(
//                 &mut rng,
//                 s2k,
//                 SymmetricKeyAlgorithm::AES128,
//                 &"secret".into(),
//             )
//             .unwrap();

//         let armored = encrypted.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-password.asc", &armored).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         let decrypted = parsed.decrypt_with_password(&"secret".into()).unwrap();
//         assert_eq!(compressed_msg, decrypted);
//     }

//     fn password_encryption_seipdv2(aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) {
//         let _ = pretty_env_logger::try_init();

//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
//         let s2k = StringToKey::new_default(&mut rng);

//         let encrypted = compressed_msg
//             .encrypt_with_password_seipdv2(
//                 &mut rng,
//                 s2k,
//                 sym,
//                 aead,
//                 ChunkSize::default(),
//                 &"secret".into(),
//             )
//             .unwrap();

//         let armored = encrypted.to_armored_bytes(None.into()).unwrap();

//         // fs::write("./message-password.asc", &armored).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

//         let decrypted = parsed.decrypt_with_password(&"secret".into()).unwrap();
//         assert_eq!(compressed_msg, decrypted);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_ocb_aes128() {
//         password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_eax_aes128() {
//         password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_gcm_aes128() {
//         password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES128);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_ocb_aes192() {
//         password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_eax_aes192() {
//         password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_gcm_aes192() {
//         password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES192);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_ocb_aes256() {
//         password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_eax_aes256() {
//         password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_password_encryption_seipdv2_gcm_aes256() {
//         password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES256);
//     }

//     #[test]
//     fn test_no_plaintext_decryption() {
//         // Invalid message "encrypted" with plaintext algorithm.
//         // Generated with the Python script below.
//         let msg_raw = b"\xc3\x04\x04\x00\x00\x08\xd2-\x01\x00\x00\xcb\x12b\x00\x00\x00\x00\x00Hello world!\xd3\x14\xc3\xadw\x022\x05\x0ek'k\x8d\x12\xaa8\r'\x8d\xc0\x82)";
//         /*
//                 import hashlib
//                 import sys
//                 data = (
//                     b"\xc3"  # PTag = 11000011, new packet format, tag 3 = SKESK
//                     b"\x04"  # Packet length, 4
//                     b"\x04"  # Version number, 4
//                     b"\x00"  # Algorithm, plaintext
//                     b"\x00\x08"  # S2K specifier, Simple S2K, SHA256
//                     b"\xd2"  # PTag = 1101 0010, new packet format, tag 18 = SEIPD
//                     b"\x2d"  # Packet length, 45
//                     b"\x01"  # Version number, 1
//                 )
//                 inner_data = (
//                     b"\x00\x00"  # IV
//                     b"\xcb"  # PTag = 11001011, new packet format, tag 11 = literal data packet
//                     b"\x12"  # Packet length, 18
//                     b"\x62"  # Binary data ('b')
//                     b"\x00"  # No filename, empty filename length
//                     b"\x00\x00\x00\x00"  # Date
//                     b"Hello world!"
//                 )
//                 data += inner_data
//                 data += (
//                     b"\xd3"  # Modification Detection Code packet, tag 19
//                     b"\x14"  # MDC packet length, 20 bytes
//                 )
//                 data += hashlib.new("SHA1", inner_data + b"\xd3\x14").digest()
//                 print(data)
//         */
//         let msg = Message::from_bytes(&msg_raw[..]).unwrap();

//         // Before the fix message eventually decrypted to
//         //   Literal(LiteralData { packet_version: New, mode: Binary, created: 1970-01-01T00:00:00Z, file_name: "", data: "48656c6c6f20776f726c6421" })
//         // where "48656c6c6f20776f726c6421" is an encoded "Hello world!" string.
//         assert!(msg
//             .decrypt_with_password(&"foobarbaz".into())
//             .err()
//             .unwrap()
//             .to_string()
//             .contains("plaintext"));
//     }

//     #[test]
//     fn test_x25519_signing_string() {
//         let _ = pretty_env_logger::try_init();

//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();

//         let pkey = skey.public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//         assert!(lit_msg.verify(&*pkey).is_err()); // Unsigned message shouldn't verify

//         let signed_msg = lit_msg
//             .sign(&mut rng, &*skey, &"".into(), HashAlgorithm::Sha256)
//             .unwrap();

//         let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-string-signed-x25519.asc", &armored).unwrap();

//         signed_msg.verify(&*pkey).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         parsed.verify(&*pkey).unwrap();
//     }

//     #[test]
//     fn test_x25519_signing_bytes() {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();

//         let pkey = skey.public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]).unwrap();
//         let signed_msg = lit_msg
//             .sign(&mut rng, &*skey, &"".into(), HashAlgorithm::Sha256)
//             .unwrap();

//         let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-bytes-signed-x25519.asc", &armored).unwrap();

//         signed_msg.verify(&*pkey).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         parsed.verify(&*pkey).unwrap();
//     }

//     #[test]
//     fn test_x25519_signing_bytes_compressed() {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();

//         let pkey = skey.public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]).unwrap();
//         let signed_msg = lit_msg
//             .sign(&mut rng, &*skey, &"".into(), HashAlgorithm::Sha256)
//             .unwrap();
//         let compressed_msg = signed_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

//         let armored = compressed_msg.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-bytes-compressed-signed-x25519.asc", &armored).unwrap();

//         signed_msg.verify(&*pkey).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         parsed.verify(&*pkey).unwrap();
//     }

//     #[test]
//     fn test_rsa_signing_string() {
//         for _ in 0..100 {
//             let (skey, _headers) = SignedSecretKey::from_armor_single(
//                 fs::File::open(
//                     "./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc",
//                 )
//                 .unwrap(),
//             )
//             .unwrap();

//             let pkey = skey.public_key();
//             let mut rng = ChaCha8Rng::seed_from_u64(0);

//             let lit_msg = Message::new_literal("hello.txt", "hello world\n").unwrap();
//             let signed_msg = lit_msg
//                 .sign(&mut rng, &*skey, &"test".into(), HashAlgorithm::Sha256)
//                 .unwrap();

//             let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
//             // fs::write("./message-string-signed-rsa.asc", &armored).unwrap();

//             signed_msg.verify(&*pkey).unwrap();

//             let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//             parsed.verify(&*pkey).unwrap();
//         }
//     }

//     #[test]
//     fn test_rsa_signing_bytes() {
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
//                 .unwrap(),
//         )
//         .unwrap();

//         let pkey = skey.public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]).unwrap();
//         let signed_msg = lit_msg
//             .sign(&mut rng, &*skey, &"test".into(), HashAlgorithm::Sha256)
//             .unwrap();

//         let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-bytes-signed-rsa.asc", &armored).unwrap();

//         signed_msg.verify(&*pkey).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         parsed.verify(&*pkey).unwrap();
//     }

//     #[test]
//     fn test_rsa_signing_bytes_compressed() {
//         let _ = pretty_env_logger::try_init();

//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
//                 .unwrap(),
//         )
//         .unwrap();

//         let pkey = skey.public_key();
//         let mut rng = ChaCha8Rng::seed_from_u64(0);

//         let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]).unwrap();
//         let signed_msg = lit_msg
//             .sign(&mut rng, &*skey, &"test".into(), HashAlgorithm::Sha256)
//             .unwrap();

//         let compressed_msg = signed_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
//         let armored = compressed_msg.to_armored_bytes(None.into()).unwrap();
//         // fs::write("./message-bytes-compressed-signed-rsa.asc", &armored).unwrap();

//         signed_msg.verify(&*pkey).unwrap();

//         let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
//         parsed.verify(&*pkey).unwrap();
//     }

//     #[test]
//     fn test_text_signature_normalization() {
//         // Test verifying an inlined signed message.
//         //
//         // The signature type is 0x01 ("Signature of a canonical text document").
//         //
//         // The literal data packet (which is in binary mode) contains the output of:
//         // echo -en "foo\nbar\r\nbaz"
//         //
//         // RFC 9580 mandates that the hash for signature type 0x01 has to be calculated over normalized line endings,
//         // so the hash for this message is calculated over "foo\r\nbar\r\nbaz".
//         //
//         // So it must also be verified against a hash digest over this normalized format.
//         let (signed_msg, _header) = Message::from_armor_single(
//             fs::File::open("./tests/unit-tests/text_signature_normalization.msg").unwrap(),
//         )
//         .unwrap();

//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/unit-tests/text_signature_normalization_alice.key").unwrap(),
//         )
//         .unwrap();

//         // Manually find the signing subkey
//         let signing = skey
//             .secret_subkeys
//             .iter()
//             .find(|key| {
//                 key.key_id() == KeyId::from([0x64, 0x35, 0x7E, 0xB6, 0xBB, 0x55, 0xDE, 0x12])
//             })
//             .unwrap();

//         // And transform it into a public subkey for signature verification
//         let verify = signing.public_key();

//         // verify the signature with alice's signing subkey
//         signed_msg.verify(&verify).expect("signature seems bad");
//     }

//     /// Tests that decompressing compression quine does not result in stack overflow.
//     /// quine.out comes from <https://mumble.net/~campbell/misc/pgp-quine/>
//     /// See <https://mumble.net/~campbell/2013/10/08/compression> for details.
//     #[test]
//     fn test_compression_quine() {
//         // Public key does not matter as the message is not signed.
//         let (skey, _headers) = SignedSecretKey::from_armor_single(
//             fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
//         )
//         .unwrap();
//         let pkey = skey.public_key();

//         let msg = include_bytes!("../../../tests/quine.out");
//         let msg = Message::from_bytes(&msg[..]).unwrap();
//         assert!(msg.get_content().is_err());
//         assert!(msg.verify(&*pkey).is_err());
//     }

//     // Sample Version 6 Certificate (Transferable Public Key)
//     // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat
//     const ANNEX_A_3: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

// xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
// GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
// KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
// gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
// QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
// +eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
// BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
// j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
// I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
// -----END PGP PUBLIC KEY BLOCK-----";

//     // Sample Version 6 Secret Key (Transferable Secret Key)
//     // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key
//     const ANNEX_A_4: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

// xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
// exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
// BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
// 2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
// RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
// 7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
// LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
// GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
// 2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
// M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
// k0mXubZvyl4GBg==
// -----END PGP PRIVATE KEY BLOCK-----";

//     /// Verify Cleartext Signed Message
//     ///
//     /// Test data from RFC 9580, see
//     /// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-cleartext-signed-mes
//     #[test]
//     fn test_v6_annex_a_6() {
//         let (ssk, _) = SignedPublicKey::from_string(ANNEX_A_3).expect("SSK from armor");

//         let msg = "-----BEGIN PGP SIGNED MESSAGE-----

// What we need from the grocery store:

// - - tofu
// - - vegetables
// - - noodles

// -----BEGIN PGP SIGNATURE-----

// wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
// 2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
// /FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
// NK2ay45cX1IVAQ==
// -----END PGP SIGNATURE-----";

//         let (msg, _) = CleartextSignedMessage::from_string(msg).unwrap();

//         msg.verify(&ssk).expect("verify");
//     }

//     /// Verify Inline Signed Message
//     ///
//     /// Test data from RFC 9580, see
//     /// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-inline-signed-messag
//     #[test]
//     fn test_v6_annex_a_7() {
//         let (ssk, _) = SignedPublicKey::from_string(ANNEX_A_3).expect("SSK from armor");

//         let msg = "-----BEGIN PGP MESSAGE-----

// xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk
// 1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv
// bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k
// bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l
// JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ
// b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj
// FtCgazStmsuOXF9SFQE=
// -----END PGP MESSAGE-----";

//         let (msg, _) = Message::from_string(msg).unwrap();

//         msg.verify(&ssk).expect("verify");
//     }

//     /// Decrypt an X25519-AEAD-OCB Encrypted Packet Sequence
//     ///
//     /// Test data from RFC 9580, see
//     /// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-x25519-aead-ocb-encr
//     #[test]
//     fn test_v6_annex_a_8() {
//         let (ssk, _) = SignedSecretKey::from_string(ANNEX_A_4).expect("SSK from armor");

//         // A.8. Sample X25519-AEAD-OCB Decryption
//         let msg = "-----BEGIN PGP MESSAGE-----

// wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO
// WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS
// aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l
// yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo
// bhF30A+IitsxxA==
// -----END PGP MESSAGE-----";

//         let (message, _) = Message::from_string(msg).expect("ok");
//         let (dec, _) = message
//             .decrypt(&[Password::empty()], &[&ssk])
//             .expect("decrypt");

//         let decrypted =
//             String::from_utf8(dec.get_literal().expect("literal").data().to_vec()).expect("utf8");

//         assert_eq!(&decrypted, "Hello, world!");
//     }
// }
