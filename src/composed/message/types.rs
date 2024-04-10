use std::io;

use bstr::BStr;
use chrono::SubsecRound;
use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::Compression;
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

use crate::armor;
use crate::composed::message::decrypt::*;
use crate::composed::shared::Deserializable;
use crate::composed::signed_key::SignedSecretKey;
use crate::composed::StandaloneSignature;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{
    write_packet, CompressedData, LiteralData, OnePassSignature, Packet,
    PublicKeyEncryptedSessionKey, Signature, SignatureConfig, SignatureType, Subpacket,
    SubpacketData, SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey,
};
use crate::ser::Serialize;
use crate::types::{
    CompressionAlgorithm, KeyId, KeyTrait, KeyVersion, PublicKeyTrait, SecretKeyTrait, StringToKey,
    Tag,
};

/// An [OpenPGP message](https://tools.ietf.org/html/rfc4880.html#section-11.3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Literal(LiteralData),
    Compressed(CompressedData),
    Signed {
        /// nested message
        message: Option<Box<Message>>,
        /// for signature packets that contain a one pass message
        one_pass_signature: Option<OnePassSignature>,
        // actual signature
        signature: Signature,
    },
    Encrypted {
        esk: Vec<Esk>,
        edata: Edata,
    },
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

impl Serialize for Esk {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => write_packet(writer, k),
            Esk::SymKeyEncryptedSessionKey(k) => write_packet(writer, k),
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

/// Encrypted Data
/// Symmetrically Encrypted Data Packet |
/// Symmetrically Encrypted Integrity Protected Data Packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edata {
    SymEncryptedData(SymEncryptedData),
    SymEncryptedProtectedData(SymEncryptedProtectedData),
}

impl Serialize for Edata {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Edata::SymEncryptedData(d) => write_packet(writer, d),
            Edata::SymEncryptedProtectedData(d) => write_packet(writer, d),
        }
    }
}

impl_try_from_into!(
    Edata,
    SymEncryptedData => SymEncryptedData,
    SymEncryptedProtectedData => SymEncryptedProtectedData
);

impl TryFrom<Packet> for Edata {
    type Error = Error;

    fn try_from(other: Packet) -> Result<Edata> {
        match other {
            Packet::SymEncryptedData(d) => Ok(Edata::SymEncryptedData(d)),
            Packet::SymEncryptedProtectedData(d) => Ok(Edata::SymEncryptedProtectedData(d)),
            _ => Err(format_err!("not a valid edata packet: {:?}", other)),
        }
    }
}

impl From<Edata> for Packet {
    fn from(other: Edata) -> Packet {
        match other {
            Edata::SymEncryptedData(d) => Packet::SymEncryptedData(d),
            Edata::SymEncryptedProtectedData(d) => Packet::SymEncryptedProtectedData(d),
        }
    }
}

impl Edata {
    pub fn data(&self) -> &[u8] {
        match self {
            Edata::SymEncryptedData(d) => d.data(),
            Edata::SymEncryptedProtectedData(d) => d.data_as_slice(),
        }
    }

    pub fn tag(&self) -> Tag {
        match self {
            Edata::SymEncryptedData(_) => Tag::SymEncryptedData,
            Edata::SymEncryptedProtectedData(_) => Tag::SymEncryptedProtectedData,
        }
    }

    fn version(&self) -> Option<usize> {
        match self {
            Edata::SymEncryptedData(_) => None,
            Edata::SymEncryptedProtectedData(d) => Some(d.version()),
        }
    }

    pub fn decrypt(&self, key: PlainSessionKey) -> Result<Message> {
        let protected = self.tag() == Tag::SymEncryptedProtectedData;
        debug!("decrypting protected = {:?}", protected);

        match key {
            PlainSessionKey::V4 { sym_alg, key } => {
                ensure!(
                    sym_alg != SymmetricKeyAlgorithm::Plaintext,
                    "session key algorithm cannot be plaintext"
                );

                match self {
                    Self::SymEncryptedProtectedData(p) => {
                        ensure_eq!(
                            self.version(),
                            Some(1),
                            "Version missmatch between key and integrity packet"
                        );
                        let data = p.decrypt(&key, Some(sym_alg))?;
                        Message::from_bytes(&data[..])
                    }
                    Self::SymEncryptedData(p) => {
                        ensure_eq!(
                            self.version(),
                            None,
                            "Version missmatch between key and integrity packet"
                        );
                        let mut data = p.data().to_vec();
                        let res = sym_alg.decrypt(&key, &mut data)?;
                        Message::from_bytes(res)
                    }
                }
            }
            PlainSessionKey::V5 { .. } => match self {
                Self::SymEncryptedProtectedData(_p) => {
                    ensure_eq!(
                        self.version(),
                        Some(2),
                        "Version missmatch between key and integrity packet"
                    );
                    unimplemented_err!("V5 decryption");
                }
                Self::SymEncryptedData(_) => {
                    bail!("invalid packet combination");
                }
            },
            PlainSessionKey::V6 { key } => {
                match self {
                    Self::SymEncryptedProtectedData(p) => {
                        let decrypted_packets = p.decrypt(&key, None)?;

                        let mut messages = Message::from_bytes_many(&decrypted_packets[..]);
                        // First message is the one we want to return
                        let Some(message) = messages.next() else {
                            bail!("no valid message found");
                        };
                        let message = message?;

                        // The only other message allowed is a padding packet, which will be skipped
                        // by the parser, so check that we have only a single message.
                        if let Some(msg) = messages.next() {
                            bail!("unexpected message: {:?}", msg);
                        }

                        Ok(message)
                    }
                    Self::SymEncryptedData(_) => {
                        bail!("invalid packet combination");
                    }
                }
            }
        }
    }
}

impl Serialize for Message {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Message::Literal(data) => write_packet(writer, data),
            Message::Compressed(data) => write_packet(writer, data),
            Message::Signed {
                message,
                one_pass_signature,
                signature,
                ..
            } => {
                if let Some(ops) = one_pass_signature {
                    write_packet(writer, ops)?;
                }
                if let Some(message) = message {
                    (**message).to_writer(writer)?;
                }

                write_packet(writer, signature)?;

                Ok(())
            }
            Message::Encrypted { esk, edata, .. } => {
                for e in esk {
                    e.to_writer(writer)?;
                }
                edata.to_writer(writer)?;

                Ok(())
            }
        }
    }
}

impl Message {
    pub fn new_literal(file_name: impl AsRef<BStr>, data: &str) -> Self {
        Message::Literal(LiteralData::from_str(file_name.as_ref(), data))
    }

    pub fn new_literal_bytes(file_name: impl AsRef<BStr>, data: &[u8]) -> Self {
        Message::Literal(LiteralData::from_bytes(file_name.as_ref(), data))
    }

    /// Compresses the message.
    pub fn compress(&self, alg: CompressionAlgorithm) -> Result<Self> {
        let data = match alg {
            CompressionAlgorithm::Uncompressed => {
                let mut data = Vec::new();
                self.to_writer(&mut data)?;
                data
            }
            CompressionAlgorithm::ZIP => {
                let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                self.to_writer(&mut enc)?;
                enc.finish()?
            }
            CompressionAlgorithm::ZLIB => {
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                self.to_writer(&mut enc)?;
                enc.finish()?
            }
            CompressionAlgorithm::BZip2 => unimplemented_err!("BZip2"),
            CompressionAlgorithm::Private10 | CompressionAlgorithm::Other(_) => {
                unsupported_err!("CompressionAlgorithm {} is unsupported", u8::from(alg))
            }
        };

        Ok(Message::Compressed(CompressedData::from_compressed(
            alg, data,
        )))
    }

    /// Decompresses the data if compressed.
    pub fn decompress(self) -> Result<Self> {
        match self {
            Message::Compressed(data) => Message::from_bytes(data.decompress()?),
            _ => Ok(self),
        }
    }

    /// Encrypt the message to the list of passed in public keys.
    pub fn encrypt_to_keys<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        alg: SymmetricKeyAlgorithm,
        pkeys: &[&impl PublicKeyTrait],
    ) -> Result<Self> {
        // 1. Generate a session key.
        let session_key = alg.new_session_key(rng);

        // 2. Encrypt (pub) the session key, to each PublicKey.
        let esk = pkeys
            .iter()
            .map(|pkey| {
                let pkes =
                    PublicKeyEncryptedSessionKey::from_session_key(rng, &session_key, alg, pkey)?;
                Ok(Esk::PublicKeyEncryptedSessionKey(pkes))
            })
            .collect::<Result<_>>()?;

        // 3. Encrypt (sym) the data using the session key.
        self.encrypt_symmetric(rng, esk, alg, session_key)
    }

    /// Encrypt the message using the given password.
    pub fn encrypt_with_password<R, F>(
        &self,
        rng: &mut R,
        s2k: StringToKey,
        alg: SymmetricKeyAlgorithm,
        msg_pw: F,
    ) -> Result<Self>
    where
        R: Rng + CryptoRng,
        F: FnOnce() -> String + Clone,
    {
        // 1. Generate a session key.
        let session_key = alg.new_session_key(rng);

        // 2. Encrypt (sym) the session key using the provided password.
        let skesk = Esk::SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey::encrypt(
            msg_pw,
            &session_key,
            s2k,
            alg,
        )?);

        // 3. Encrypt (sym) the data using the session key.
        self.encrypt_symmetric(rng, vec![skesk], alg, session_key)
    }

    /// Symmetrically encrypts oneself using the provided `session_key`.
    fn encrypt_symmetric<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        esk: Vec<Esk>,
        alg: SymmetricKeyAlgorithm,
        session_key: Vec<u8>,
    ) -> Result<Self> {
        let data = self.to_bytes()?;

        let edata = Edata::SymEncryptedProtectedData(SymEncryptedProtectedData::encrypt_with_rng(
            rng,
            alg,
            &session_key,
            &data,
        )?);

        Ok(Message::Encrypted { esk, edata })
    }

    /// Sign this message using the provided key.
    pub fn sign<F>(
        self,
        key: &impl SecretKeyTrait,
        key_pw: F,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Self>
    where
        F: FnOnce() -> String,
    {
        let key_id = key.key_id();
        let algorithm = key.algorithm();
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                SmallVec::from_slice(&key.fingerprint()),
            )),
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            )),
        ];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key_id.clone()))];

        let (typ, signature) = match self {
            Message::Literal(ref l) => {
                let typ = if l.is_binary() {
                    SignatureType::Binary
                } else {
                    SignatureType::Text
                };

                let signature_config = SignatureConfig::new_v4(
                    Default::default(),
                    typ,
                    algorithm,
                    hash_algorithm,
                    hashed_subpackets,
                    unhashed_subpackets,
                );
                (typ, signature_config.sign(key, key_pw, l.data())?)
            }
            _ => {
                let typ = SignatureType::Binary;
                let signature_config = SignatureConfig::new_v4(
                    Default::default(),
                    typ,
                    algorithm,
                    hash_algorithm,
                    hashed_subpackets,
                    unhashed_subpackets,
                );

                let data = self.to_bytes()?;
                let signature = signature_config.sign(key, key_pw, &data[..])?;

                (typ, signature)
            }
        };
        let ops = OnePassSignature::from_details(typ, hash_algorithm, algorithm, key_id);

        Ok(Message::Signed {
            message: Some(Box::new(self)),
            one_pass_signature: Some(ops),
            signature,
        })
    }

    /// Convert the message to a standalone signature according to the cleartext framework.
    pub fn into_signature(self) -> StandaloneSignature {
        match self {
            Message::Signed { signature, .. } => StandaloneSignature::new(signature),
            _ => panic!("only signed messages can be converted to standalone signature messages"),
        }
    }

    /// Verify this message.
    /// For signed messages this verifies the signature and for compressed messages
    /// they are decompressed and checked for signatures to verify.
    ///
    /// Decompresses up to one layer of compressed data.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        self.verify_internal(key, true)
    }

    /// Verifies this message.
    /// For signed messages this verifies the signature.
    ///
    /// If `decompress` is true and the message is compressed,
    /// the message is decompressed and verified.
    fn verify_internal(&self, key: &impl PublicKeyTrait, decompress: bool) -> Result<()> {
        match self {
            Message::Signed {
                signature, message, ..
            } => {
                if let Some(message) = message {
                    match **message {
                        Message::Literal(ref data) => signature.verify(key, data.data()),
                        _ => {
                            let data = message.to_bytes()?;
                            signature.verify(key, &data[..])
                        }
                    }
                } else {
                    unimplemented_err!("no message, what to do?");
                }
            }
            Message::Compressed(data) => {
                if decompress {
                    let msg = Message::from_bytes(data.decompress()?)?;
                    msg.verify_internal(key, false)
                } else {
                    bail!("Recursive decompression not allowed");
                }
            }
            // We don't know how to verify a signature for other Message types, and shouldn't return Ok
            _ => Err(Error::Unsupported(format!(
                "Unexpected message format: {self:?}",
            ))),
        }
    }

    /// Returns a list of [KeyId]s that the message is encrypted to. For non encrypted messages this list is empty.
    pub fn get_recipients(&self) -> Vec<&KeyId> {
        match self {
            Message::Encrypted { esk, .. } => esk
                .iter()
                .filter_map(|e| match e {
                    Esk::PublicKeyEncryptedSessionKey(k) => Some(k.id()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt<G>(&self, key_pw: G, keys: &[&SignedSecretKey]) -> Result<(Message, Vec<KeyId>)>
    where
        G: FnOnce() -> String + Clone,
    {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(key_pw, keys),
                None => bail!("not encrypted"),
            },
            Message::Encrypted { esk, edata, .. } => {
                let valid_keys = keys
                    .iter()
                    .filter_map(|key| {
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
                                    .map(KeyTrait::key_id)
                                    .collect::<Vec<_>>()
                            );

                            // find the key with the matching key id

                            if &key.primary_key.key_id() == esk_packet.id() {
                                encoding_key = Some(&key.primary_key);
                            }

                            if encoding_key.is_none() {
                                encoding_subkey = key
                                    .secret_subkeys
                                    .iter()
                                    .find(|&subkey| &subkey.key_id() == esk_packet.id());
                            }

                            if encoding_key.is_some() || encoding_subkey.is_some() {
                                packet = Some(esk_packet);
                                break;
                            }
                        }

                        packet.map(|packet| (packet, encoding_key, encoding_subkey))
                    })
                    .collect::<Vec<_>>();

                if valid_keys.is_empty() {
                    return Err(Error::MissingKey);
                }

                let session_keys = valid_keys
                    .iter()
                    .map(|(packet, encoding_key, encoding_subkey)| {
                        if let Some(ek) = encoding_key {
                            Ok((
                                ek.key_id(),
                                decrypt_session_key(ek, key_pw.clone(), packet.mpis())?,
                            ))
                        } else if let Some(ek) = encoding_subkey {
                            Ok((
                                ek.key_id(),
                                decrypt_session_key(ek, key_pw.clone(), packet.mpis())?,
                            ))
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
    pub fn decrypt_with_password<F>(&self, msg_pw: F) -> Result<Message>
    where
        F: FnOnce() -> String + Clone,
    {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => match message {
                Some(ref message) => message.decrypt_with_password(msg_pw),
                None => bail!("not encrypted"),
            },
            Message::Encrypted { esk, edata, .. } => {
                // TODO: handle multiple passwords
                let skesk = esk.iter().find_map(|esk| match esk {
                    Esk::SymKeyEncryptedSessionKey(k) => Some(k),
                    _ => None,
                });

                ensure!(skesk.is_some(), "message is not password protected");

                let session_key =
                    decrypt_session_key_with_password(skesk.expect("checked above"), msg_pw)?;
                edata.decrypt(session_key)
            }
        }
    }

    /// Check if this message is a signature, that was signed with a one pass signature.
    pub fn is_one_pass_signed(&self) -> bool {
        match self {
            Message::Signed {
                one_pass_signature, ..
            } => one_pass_signature.is_some(),
            _ => false,
        }
    }

    pub fn is_literal(&self) -> bool {
        match self {
            Message::Literal { .. } => true,
            Message::Signed { message, .. } => message
                .as_ref()
                .map(|msg| msg.is_literal())
                .unwrap_or_default(),
            _ => false,
        }
    }

    pub fn get_literal(&self) -> Option<&LiteralData> {
        match self {
            Message::Literal(ref data) => Some(data),
            Message::Signed { message, .. } => message.as_ref().and_then(|msg| msg.get_literal()),
            _ => None,
        }
    }

    /// Returns the underlying content and `None` if the message is encrypted.
    ///
    /// Decompresses up to one layer of compressed data.
    pub fn get_content(&self) -> Result<Option<Vec<u8>>> {
        self.get_content_internal(true)
    }

    /// Returns the underlying content and `None` if the message is encrypted.
    ///
    /// If `decompress` is true, may decompress a compressed message.
    fn get_content_internal(&self, decompress: bool) -> Result<Option<Vec<u8>>> {
        match self {
            Message::Literal(ref data) => Ok(Some(data.data().to_vec())),
            Message::Signed { message, .. } => Ok(message
                .as_ref()
                .and_then(|m| m.get_literal())
                .map(|l| l.data().to_vec())),
            Message::Compressed(data) => {
                if decompress {
                    let msg = Message::from_bytes(data.decompress()?)?;
                    msg.get_content_internal(false)
                } else {
                    bail!("Recursive decompression not allowed");
                }
            }
            Message::Encrypted { .. } => Ok(None),
        }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::Message,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, opts)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use rand::thread_rng;
    use std::fs;

    #[test]
    fn test_compression_zlib() {
        let lit_msg = Message::new_literal("hello-zlib.txt", "hello world");

        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_compression_zip() {
        let lit_msg = Message::new_literal("hello-zip.txt", "hello world");

        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZIP).unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_compression_uncompressed() {
        let lit_msg = Message::new_literal("hello.txt", "hello world");

        let compressed_msg = lit_msg
            .compress(CompressionAlgorithm::Uncompressed)
            .unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_rsa_encryption() {
        use rand::SeedableRng;

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap(),
        )
        .unwrap();

        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();
        let mut rng = rand::rngs::StdRng::seed_from_u64(100);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(100);

        let lit_msg = Message::new_literal("hello.txt", "hello world\n");
        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

        // Encrypt and test that rng is the only source of randomness.
        let encrypted = compressed_msg
            .encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
            .unwrap();
        let encrypted2 = compressed_msg
            .encrypt_to_keys(&mut rng2, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
            .unwrap();
        assert_eq!(encrypted, encrypted2);

        let armored = encrypted.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-rsa.asc", &armored).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

        let decrypted = parsed.decrypt(|| "test".into(), &[&skey]).unwrap().0;

        assert_eq!(compressed_msg, decrypted);
    }

    #[test]
    fn test_x25519_encryption() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();
        let mut rng = thread_rng();

        let lit_msg = Message::new_literal("hello.txt", "hello world\n");
        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
        for _ in 0..1000 {
            let encrypted = compressed_msg
                .encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
                .unwrap();

            let armored = encrypted.to_armored_bytes(None.into()).unwrap();
            fs::write("./message-x25519.asc", &armored).unwrap();

            let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

            let decrypted = parsed.decrypt(|| "".into(), &[&skey]).unwrap().0;

            assert_eq!(compressed_msg, decrypted);
        }
    }

    #[test]
    fn test_password_encryption() {
        let _ = pretty_env_logger::try_init();

        let mut rng = thread_rng();

        let lit_msg = Message::new_literal("hello.txt", "hello world\n");
        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

        let s2k = StringToKey::new_default(&mut rng);

        let encrypted = compressed_msg
            .encrypt_with_password(&mut rng, s2k, SymmetricKeyAlgorithm::AES128, || {
                "secret".into()
            })
            .unwrap();

        let armored = encrypted.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-password.asc", &armored).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;

        let decrypted = parsed.decrypt_with_password(|| "secret".into()).unwrap();

        assert_eq!(compressed_msg, decrypted);
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
        assert!(msg
            .decrypt_with_password(|| "foobarbaz".into())
            .err()
            .unwrap()
            .to_string()
            .contains("plaintext"));
    }

    #[test]
    fn test_x25519_signing_string() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        let pkey = skey.public_key();

        let lit_msg = Message::new_literal("hello.txt", "hello world\n");
        assert!(lit_msg.verify(&pkey).is_err()); // Unsigned message shouldn't verify

        let signed_msg = lit_msg
            .sign(&skey, || "".into(), HashAlgorithm::SHA2_256)
            .unwrap();

        let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-string-signed-x25519.asc", &armored).unwrap();

        signed_msg.verify(&pkey).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
        parsed.verify(&pkey).unwrap();
    }

    #[test]
    fn test_x25519_signing_bytes() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        let pkey = skey.public_key();

        let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]);
        let signed_msg = lit_msg
            .sign(&skey, || "".into(), HashAlgorithm::SHA2_256)
            .unwrap();

        let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-bytes-signed-x25519.asc", &armored).unwrap();

        signed_msg.verify(&pkey).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
        parsed.verify(&pkey).unwrap();
    }

    #[test]
    fn test_x25519_signing_bytes_compressed() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        let pkey = skey.public_key();

        let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]);
        let signed_msg = lit_msg
            .sign(&skey, || "".into(), HashAlgorithm::SHA2_256)
            .unwrap();
        let compressed_msg = signed_msg.compress(CompressionAlgorithm::ZLIB).unwrap();

        let armored = compressed_msg.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-bytes-compressed-signed-x25519.asc", &armored).unwrap();

        signed_msg.verify(&pkey).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
        parsed.verify(&pkey).unwrap();
    }

    #[test]
    fn test_rsa_signing_string() {
        for _ in 0..100 {
            let (skey, _headers) = SignedSecretKey::from_armor_single(
                fs::File::open(
                    "./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc",
                )
                .unwrap(),
            )
            .unwrap();

            let pkey = skey.public_key();

            let lit_msg = Message::new_literal("hello.txt", "hello world\n");
            let signed_msg = lit_msg
                .sign(&skey, || "test".into(), HashAlgorithm::SHA2_256)
                .unwrap();

            let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
            fs::write("./message-string-signed-rsa.asc", &armored).unwrap();

            signed_msg.verify(&pkey).unwrap();

            let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
            parsed.verify(&pkey).unwrap();
        }
    }

    #[test]
    fn test_rsa_signing_bytes() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap(),
        )
        .unwrap();

        let pkey = skey.public_key();

        let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]);
        let signed_msg = lit_msg
            .sign(&skey, || "test".into(), HashAlgorithm::SHA2_256)
            .unwrap();

        let armored = signed_msg.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-bytes-signed-rsa.asc", &armored).unwrap();

        signed_msg.verify(&pkey).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
        parsed.verify(&pkey).unwrap();
    }

    #[test]
    fn test_rsa_signing_bytes_compressed() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap(),
        )
        .unwrap();

        let pkey = skey.public_key();

        let lit_msg = Message::new_literal_bytes("hello.txt", &b"hello world\n"[..]);
        let signed_msg = lit_msg
            .sign(&skey, || "test".into(), HashAlgorithm::SHA2_256)
            .unwrap();

        let compressed_msg = signed_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
        let armored = compressed_msg.to_armored_bytes(None.into()).unwrap();
        fs::write("./message-bytes-compressed-signed-rsa.asc", &armored).unwrap();

        signed_msg.verify(&pkey).unwrap();

        let parsed = Message::from_armor_single(&armored[..]).unwrap().0;
        parsed.verify(&pkey).unwrap();
    }

    #[test]
    fn test_text_signature_normalization() {
        // Test verifying an inlined signed message.
        //
        // The signature type is 0x01 ("Signature of a canonical text document").
        //
        // The literal data packet (which is in binary mode) contains the output of:
        // echo -en "foo\nbar\r\nbaz"
        //
        // RFC 4880 mandates that the hash for signature type 0x01 has to be calculated over normalized line endings,
        // so the hash for this message is calculated over "foo\r\nbar\r\nbaz".
        //
        // So it must also be verified against a hash digest over this normalized format.
        let (signed_msg, _header) = Message::from_armor_single(
            fs::File::open("./tests/unit-tests/text_signature_normalization.msg").unwrap(),
        )
        .unwrap();

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/unit-tests/text_signature_normalization_alice.key").unwrap(),
        )
        .unwrap();

        // Manually find the signing subkey
        let signing = skey
            .secret_subkeys
            .iter()
            .find(|key| {
                key.key_id()
                    == KeyId::from_slice(&[0x64, 0x35, 0x7E, 0xB6, 0xBB, 0x55, 0xDE, 0x12]).unwrap()
            })
            .unwrap();

        // And transform it into a public subkey for signature verification
        let verify = signing.public_key();

        // verify the signature with alice's signing subkey
        signed_msg.verify(&verify).expect("signature seems bad");
    }

    /// Tests that decompressing compression quine does not result in stack overflow.
    /// quine.out comes from <https://mumble.net/~campbell/misc/pgp-quine/>
    /// See <https://mumble.net/~campbell/2013/10/08/compression> for details.
    #[test]
    fn test_compression_quine() {
        // Public key does not matter as the message is not signed.
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        let pkey = skey.public_key();

        let msg = Message::from_bytes(&include_bytes!("../../../tests/quine.out")[..]).unwrap();
        assert!(msg.get_content().is_err());
        assert!(msg.verify(&pkey).is_err());
    }
}
