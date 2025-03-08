use std::io::{self, BufRead, Read};

use log::debug;

use crate::armor;
use crate::composed::message::decrypt::*;
use crate::composed::signed_key::SignedSecretKey;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{
    LiteralDataHeader, OnePassSignature, Packet, PacketHeader, PacketTrait,
    PublicKeyEncryptedSessionKey, Signature, SymEncryptedProtectedDataConfig,
    SymKeyEncryptedSessionKey,
};
use crate::parsing_reader::BufReadParsing;
use crate::ser::Serialize;
use crate::types::{
    EskType, KeyDetails, Password, PkeskVersion, PublicKeyTrait, SecretParams, Tag,
};

use super::reader::{
    CompressedDataReader, LiteralDataReader, PacketBodyReader, SignatureBodyReader,
    SignatureOnePassReader, SymEncryptedDataReader, SymEncryptedProtectedDataReader,
};

/// An [OpenPGP message](https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages)
/// Encrypted Message | Signed Message | Compressed Message | Literal Message.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
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
                debug_assert!(reader.is_done());
                let packet_header = reader.packet_header();
                let header = reader.data_header().clone();
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
#[allow(clippy::large_enum_variant)]
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

impl Edata<'_> {
    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::SymEncryptedData { reader } => reader.packet_header(),
            Self::SymEncryptedProtectedData { reader } => reader.packet_header(),
        }
    }

    pub fn tag(&self) -> Tag {
        self.packet_header().tag()
    }

    pub fn decrypt(&mut self, key: &PlainSessionKey) -> Result<()> {
        let protected = self.tag() == Tag::SymEncryptedProtectedData;
        debug!("decrypting protected = {:?}", protected);

        match self {
            Self::SymEncryptedProtectedData { reader } => {
                reader.decrypt(key)?;
            }
            Self::SymEncryptedData { reader } => {
                reader.decrypt(key)?;
            }
        }

        Ok(())
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
    pub fn decrypt(self, key_pw: &Password, key: &SignedSecretKey) -> Result<Message<'a>> {
        let ring = TheRing {
            secret_keys: vec![key],
            key_passwords: vec![key_pw],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt_with_password(self, msg_pw: &Password) -> Result<Message<'a>> {
        let ring = TheRing {
            message_password: vec![msg_pw],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    pub fn decrypt_with_session_key(self, session_key: PlainSessionKey) -> Result<Message<'a>> {
        let ring = TheRing {
            session_keys: vec![session_key],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    /// The most powerful and flexible way to decrypt. Give it all you know, and maybe something will come of it.
    ///
    /// If `abort_early` is true, the first available session key will be used, even if it might be wrong, or missmatch
    /// with others.
    /// If it is set to false, all provided keys, and passwords will be checked and compared.
    /// In this case, if there are different session keys found, it will error out.
    pub fn decrypt_the_ring(
        self,
        ring: TheRing<'_>,
        abort_early: bool,
    ) -> Result<(Message<'a>, RingResult)> {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("even the ring can not decrypt plaintext");
            }
            Message::Signed { reader, signature } => {
                let (reader, res) = reader.decrypt_the_ring(ring, abort_early)?;
                Ok((Message::Signed { signature, reader }, res))
            }
            Message::SignedOnePass {
                reader,
                one_pass_signature,
            } => {
                let (reader, res) = reader.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Message::SignedOnePass {
                        one_pass_signature,
                        reader,
                    },
                    res,
                ))
            }
            Message::Encrypted { esk, mut edata } => {
                // Lets go and find things, with which we can decrypt
                let (session_key, result) = ring.find_session_key(&esk, abort_early)?;
                let Some(session_key) = session_key else {
                    return Err(Error::MissingKey);
                };

                edata.decrypt(&session_key)?;
                let message = Message::from_bytes(edata)?;
                Ok((message, result))
            }
        }
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

    /// Is this a literal message?
    pub fn is_literal(&self) -> bool {
        matches!(self, Message::Literal { .. })
    }

    /// If this is a literal message, returns the literal data header
    pub fn literal_data_header(&self) -> Option<&LiteralDataHeader> {
        match self {
            Self::Literal { reader } => Some(reader.data_header()),
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

/// Like a key ring, but better, and more powerful, serving all your decryption needs.
#[derive(Debug, Default)]
pub struct TheRing<'a> {
    pub secret_keys: Vec<&'a SignedSecretKey>,
    pub key_passwords: Vec<&'a Password>,
    pub message_password: Vec<&'a Password>,
    pub session_keys: Vec<PlainSessionKey>,
}

impl TheRing<'_> {
    fn find_session_key(
        mut self,
        esk: &[Esk],
        abort_early: bool,
    ) -> Result<(Option<PlainSessionKey>, RingResult)> {
        let mut result = RingResult {
            secret_keys: vec![InnerRingResult::Unchecked; self.secret_keys.len()],
            message_password: vec![InnerRingResult::Unchecked; self.message_password.len()],
            session_keys: vec![InnerRingResult::Unchecked; self.session_keys.len()],
        };

        if abort_early {
            // Do we have a session key already?
            if !self.session_keys.is_empty() {
                let session_key = self.session_keys.remove(0);
                result.session_keys[0] = InnerRingResult::Ok;
                return Ok((Some(session_key), result));
            }
        }

        // Search ESKs

        let mut pkesks = Vec::new();
        let mut skesks = Vec::new();
        for esk in esk {
            match esk {
                Esk::PublicKeyEncryptedSessionKey(k) => pkesks.push(k),
                Esk::SymKeyEncryptedSessionKey(k) => {
                    ensure!(
                        k.sym_algorithm() != SymmetricKeyAlgorithm::Plaintext,
                        "SKESK must not use plaintext"
                    );

                    skesks.push(k)
                }
            }
        }

        let mut pkesk_session_keys = Vec::new();

        for esk in &pkesks {
            debug!("checking esk: {:?}/{:?}", esk.id(), esk.fingerprint());
            for (i, key) in self.secret_keys.iter().enumerate() {
                result.secret_keys[i] = InnerRingResult::NoMatch;

                let typ = match esk.version() {
                    PkeskVersion::V3 => EskType::V3_4,
                    PkeskVersion::V6 => EskType::V6,
                    PkeskVersion::Other(v) => {
                        unimplemented_err!("Unexpected PKESK version {}", v)
                    }
                };

                macro_rules! try_key {
                    ($skey:expr, $pkey:expr, $values:expr) => {
                        debug!("found matching key {:?}, trying to decrypt", $skey.key_id());
                        match $skey.secret_params() {
                            SecretParams::Encrypted(_) => {
                                // unlock
                                for pw in &self.key_passwords {
                                    match $skey.decrypt_session_key(pw, $values, typ) {
                                        Ok(Ok(session_key)) => {
                                            debug!("decrypted session key");
                                            result.secret_keys[i] = InnerRingResult::Ok;
                                            pkesk_session_keys.push((i, session_key));
                                            break;
                                        }
                                        Ok(Err(err)) => {
                                            debug!("failed to decrypt session key: {:?}", err);
                                            result.secret_keys[i] = InnerRingResult::Invalid;
                                            break;
                                        }
                                        Err(err) => {
                                            debug!("failed to unlock key: {:?}", err);
                                            result.secret_keys[i] =
                                                InnerRingResult::InvalidPassword;
                                        }
                                    }
                                }
                            }
                            SecretParams::Plain(sec_params) => {
                                // already unlocked
                                debug!("key is already unlocked");
                                match sec_params.decrypt($pkey.public_params(), $values, typ, $pkey)
                                {
                                    Ok(session_key) => {
                                        result.secret_keys[i] = InnerRingResult::Ok;
                                        pkesk_session_keys.push((i, session_key));
                                    }
                                    Err(err) => {
                                        debug!("failed to decrypt session key: {:?}", err);
                                        result.secret_keys[i] = InnerRingResult::Invalid;
                                    }
                                }
                            }
                        }
                    };
                }

                // check primary key
                debug!("checking primary key: {:?}", key.primary_key.key_id());
                if esk.match_identity(key.primary_key.public_key()) {
                    let values = esk.values()?;
                    try_key!(key, key.primary_key.public_key(), values);
                } else {
                    // search subkeys
                    for subkey in &key.secret_subkeys {
                        debug!("checking subkey: {:?}", subkey.key_id());
                        if esk.match_identity(&subkey.public_key()) {
                            let values = esk.values()?;
                            try_key!(subkey, subkey.key.public_key(), values);
                        }
                    }
                }
            }
        }

        // search password based esks
        let mut skesk_session_keys: Vec<(usize, PlainSessionKey)> = Vec::new();

        for esk in skesks {
            for (i, pw) in self.message_password.iter().enumerate() {
                result.message_password[i] = InnerRingResult::Invalid;

                match decrypt_session_key_with_password(esk, pw) {
                    Ok(session_key) => {
                        skesk_session_keys.push((i, session_key));
                        result.message_password[i] = InnerRingResult::Ok;
                        break;
                    }
                    Err(_err) => {
                        result.message_password[i] = InnerRingResult::Invalid;
                    }
                }
            }
        }

        // compare all session keys
        let (is_pkesk_consistent, pkesk_session_key) = if pkesk_session_keys.is_empty() {
            (true, None)
        } else {
            let sk = pkesk_session_keys.remove(0);

            let mut is_consistent = true;

            for (_i, key) in pkesk_session_keys {
                if key != sk.1 {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        let (is_skesk_consistent, skesk_session_key) = if skesk_session_keys.is_empty() {
            (true, None)
        } else {
            let sk = skesk_session_keys.remove(0);

            let mut is_consistent = true;

            for (_i, key) in skesk_session_keys {
                if key != sk.1 {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        let (is_sks_consistent, sks_session_key) = if self.session_keys.is_empty() {
            (true, None)
        } else {
            let sk = self.session_keys.remove(0);

            let mut is_consistent = true;

            for key in self.session_keys.iter() {
                if key != &sk {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        // TODO: the above fails to handle the fact that PlainSessionKey::Unknown will not compare correctly

        let is_consistent = is_sks_consistent && is_skesk_consistent && is_pkesk_consistent;

        if !is_consistent {
            bail!("inconsistent session keys detected");
        }

        if let Some((_, session_key)) = pkesk_session_key {
            return Ok((Some(session_key), result));
        }

        if let Some((_, session_key)) = skesk_session_key {
            return Ok((Some(session_key), result));
        }

        if let Some(session_key) = sks_session_key {
            return Ok((Some(session_key), result));
        }

        Ok((None, result))
    }
}

/// This is what happens if you use `TheRing`.
#[derive(Debug)]
pub struct RingResult {
    pub secret_keys: Vec<InnerRingResult>,
    pub message_password: Vec<InnerRingResult>,
    pub session_keys: Vec<InnerRingResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerRingResult {
    /// Value was not checked, due to either an earlier error
    /// or another mechanism already matching
    Unchecked,
    /// No matching ESK packet has been found
    NoMatch,
    /// Unlocking the secret key failed, due to the provided password being invalid.
    InvalidPassword,
    /// Multiple session keys have been found, and they do not match.
    InconsistentSessionKey,
    /// Decryption of the ESK has failed.
    Invalid,
    /// A session key was successfully produced
    /// The actual encrypted data decryption process can still fail.
    Ok,
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

#[cfg(test)]
mod tests {

    use std::fs;

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::crypto::aead::{AeadAlgorithm, ChunkSize};
    use crate::types::{CompressionAlgorithm, StringToKey};
    use crate::{Deserializable, MessageBuilder};

    #[test]
    fn test_compression_zlib() {
        test_compression(CompressionAlgorithm::ZLIB);
    }

    #[test]
    fn test_compression_zip() {
        test_compression(CompressionAlgorithm::ZIP);
    }

    #[test]
    fn test_compression_uncompressed() {
        test_compression(CompressionAlgorithm::Uncompressed);
    }

    #[test]
    #[cfg(feature = "bzip2")]
    fn test_compression_bzip2() {
        test_compression(CompressionAlgorithm::BZip2);
    }

    fn test_compression(alg: CompressionAlgorithm) {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let data = "hello world";
        let compressed_msg = MessageBuilder::from_bytes("hello-zlib.txt", data)
            .compression(alg)
            .to_vec(&mut rng)
            .unwrap();

        let uncompressed_msg = Message::from_bytes(&compressed_msg[..])
            .unwrap()
            .decompress()
            .unwrap()
            .as_data_string()
            .unwrap();

        assert_eq!(data, &uncompressed_msg);
    }

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

    fn x25519_encryption_seipdv2(aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let data = "hello world\n";

        for _ in 0..512 {
            let armored = MessageBuilder::from_bytes("hello.txt", data)
                .compression(CompressionAlgorithm::ZLIB)
                .seipd_v2(&mut rng, sym, aead, ChunkSize::default())
                .encrypt_to_key(&mut rng, &pkey)
                .unwrap()
                .to_armored_string(&mut rng, Default::default())
                .unwrap();

            // fs::write("./message-x25519.asc", &armored).unwrap();

            let (parsed, _headers) = Message::from_armor(armored.as_bytes()).unwrap();

            let msg = parsed.decrypt(&"".into(), &skey).unwrap();
            let mut msg = msg.decompress().unwrap();
            let text = msg.as_data_string().unwrap();

            assert_eq!(data, text);
        }
    }

    #[test]
    fn test_x25519_encryption_seipdv2_ocb_aes128() {
        x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_eax_aes128() {
        x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_gcm_aes128() {
        x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_ocb_aes192() {
        x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_eax_aes192() {
        x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_gcm_aes192() {
        x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_ocb_aes256() {
        x25519_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES256);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_eax_aes256() {
        x25519_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES256);
    }

    #[test]
    fn test_x25519_encryption_seipdv2_gcm_aes256() {
        x25519_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES256);
    }

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

    fn password_encryption_seipdv2(aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) {
        let _ = pretty_env_logger::try_init();

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let data = "hello world\n";
        let s2k = StringToKey::new_default(&mut rng);
        let armored = MessageBuilder::from_bytes("hello.txt", data)
            .seipd_v2(&mut rng, sym, aead, ChunkSize::default())
            .encrypt_with_password(&mut rng, s2k, &"secret".into())
            .unwrap()
            .to_armored_string(&mut rng, Default::default())
            .unwrap();

        // fs::write("./message-password.asc", &armored).unwrap();

        let (msg, _headers) = Message::from_armor(armored.as_bytes()).unwrap();

        let mut msg = msg.decrypt_with_password(&"secret".into()).unwrap();
        let text = msg.as_data_string().unwrap();

        assert_eq!(data, text);
    }

    #[test]
    fn test_password_encryption_seipdv2_ocb_aes128() {
        password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_password_encryption_seipdv2_eax_aes128() {
        password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_password_encryption_seipdv2_gcm_aes128() {
        password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_password_encryption_seipdv2_ocb_aes192() {
        password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_password_encryption_seipdv2_eax_aes192() {
        password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_password_encryption_seipdv2_gcm_aes192() {
        password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_password_encryption_seipdv2_ocb_aes256() {
        password_encryption_seipdv2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::AES256);
    }

    #[test]
    fn test_password_encryption_seipdv2_eax_aes256() {
        password_encryption_seipdv2(AeadAlgorithm::Eax, SymmetricKeyAlgorithm::AES256);
    }

    #[test]
    fn test_password_encryption_seipdv2_gcm_aes256() {
        password_encryption_seipdv2(AeadAlgorithm::Gcm, SymmetricKeyAlgorithm::AES256);
    }

    #[test]
    fn test_no_plaintext_decryption() {
        // Invalid message "encrypted" with plaintext algorithm.
        // Generated with the Python script below.
        let msg_raw = b"\xc3\x04\x04\x00\x00\x08\xd2-\x01\x00\x00\xcb\x12b\x00\x00\x00\x00\x00Hello world!\xd3\x14\xc3\xadw\x022\x05\x0ek'k\x8d\x12\xaa8\r'\x8d\xc0\x82)";
        /*
                import hashlib
                import sys
                data = (
                    b"\xc3"  # PTag = 11000011, new packet format, tag 3 = SKESK
                    b"\x04"  # Packet length, 4
                    b"\x04"  # Version number, 4
                    b"\x00"  # Algorithm, plaintext
                    b"\x00\x08"  # S2K specifier, Simple S2K, SHA256
                    b"\xd2"  # PTag = 1101 0010, new packet format, tag 18 = SEIPD
                    b"\x2d"  # Packet length, 45
                    b"\x01"  # Version number, 1
                )
                inner_data = (
                    b"\x00\x00"  # IV
                    b"\xcb"  # PTag = 11001011, new packet format, tag 11 = literal data packet
                    b"\x12"  # Packet length, 18
                    b"\x62"  # Binary data ('b')
                    b"\x00"  # No filename, empty filename length
                    b"\x00\x00\x00\x00"  # Date
                    b"Hello world!"
                )
                data += inner_data
                data += (
                    b"\xd3"  # Modification Detection Code packet, tag 19
                    b"\x14"  # MDC packet length, 20 bytes
                )
                data += hashlib.new("SHA1", inner_data + b"\xd3\x14").digest()
                print(data)
        */
        let msg = Message::from_bytes(&msg_raw[..]).unwrap();

        // Before the fix message eventually decrypted to
        //   Literal(LiteralData { packet_version: New, mode: Binary, created: 1970-01-01T00:00:00Z, file_name: "", data: "48656c6c6f20776f726c6421" })
        // where "48656c6c6f20776f726c6421" is an encoded "Hello world!" string.
        dbg!(&msg);
        let decrypted_err = msg
            .decrypt_with_password(&"foobarbaz".into())
            .err()
            .unwrap()
            .to_string();
        assert!(decrypted_err.contains("plaintext"), "{}", decrypted_err);
    }

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
}
