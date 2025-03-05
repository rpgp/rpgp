use std::io::{self, BufRead, BufReader};

use bytes::{Buf, Bytes, BytesMut};
#[cfg(feature = "bzip2")]
use bzip2::write::BzEncoder;
use chrono::SubsecRound;
use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::Compression;
use log::{debug, warn};
use rand::{CryptoRng, Rng};

use crate::armor;
use crate::composed::message::decrypt::*;
use crate::composed::shared::Deserializable;
use crate::composed::signed_key::SignedSecretKey;
use crate::composed::StandaloneSignature;
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{
    ChunkSize, CompressedData, LiteralData, LiteralDataHeader, OnePassSignature, Packet,
    PacketHeader, PacketTrait, PublicKeyEncryptedSessionKey, Signature, SignatureConfig,
    SignatureType, SignatureVersionSpecific, Subpacket, SubpacketData, SymEncryptedData,
    SymEncryptedProtectedData, SymKeyEncryptedSessionKey,
};
use crate::ser::Serialize;
use crate::types::{
    CompressionAlgorithm, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, PacketLength,
    Password, PkeskVersion, PublicKeyTrait, SecretKeyTrait, StringToKey, Tag,
};

use super::reader::{
    CompressedDataReader, LiteralDataReader, SymEncryptedDataReader,
    SymEncryptedProtectedDataReader,
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
    /// Signed Message: Signature Packet, OpenPGP Message | One-Pass Signed Message.
    /// One-Pass Signed Message: One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
    Signed {
        /// The actual signature
        signature: Signature,
        /// Nested message
        message: Box<Message<'a>>,
        /// for signature packets that contain a one pass message
        one_pass_signature: Option<OnePassSignature>,
    },
    /// Encrypted Message: Encrypted Data | ESK Sequence, Encrypted Data.
    Encrypted {
        /// ESK Sequence: ESK | ESK Sequence, ESK.
        esk: Vec<Esk>,
        edata: Edata<'a>,
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

impl<'a> Message<'a> {
    /// Decompresses the data if compressed.
    pub fn decompress(self) -> Result<Self> {
        match self {
            Message::Compressed { reader } => Message::from_bytes(reader.decompress()?),
            Message::Signed { message, .. } => message.decompress(),
            _ => Ok(self),
        }
    }

    /// Verify this message.
    /// For signed messages this verifies the signature and for compressed messages
    /// they are decompressed and checked for signatures to verify.
    ///
    /// Decompresses up to one layer of compressed data.
    pub fn verify(self, key: &impl PublicKeyTrait) -> Result<()> {
        self.verify_internal(key, true)
    }

    /// Verifies this message.
    /// For signed messages this verifies the signature.
    ///
    /// If `decompress` is true and the message is compressed,
    /// the message is decompressed and verified.
    fn verify_internal(self, key: &impl PublicKeyTrait, decompress: bool) -> Result<()> {
        todo!();
        // this needs a different structure, as verifying consumes the message now

        // match self {
        //     Message::Signed {
        //         signature, message, ..
        //     } => {
        //         if let Some(ref message) = message {
        //             match **message {
        //                 Message::Literal { .. } => {
        //                     todo!()
        //                     // signature.verify(key, data.data())
        //                 }
        //                 Message::Signed { ref message, .. } => {
        //                     // TODO: add api to verify the inner messages

        //                     // We need to search for the inner most non signed message for the data
        //                     let Some(ref message) = message else {
        //                         unimplemented_err!("no message, what to do?");
        //                     };
        //                     let mut current_message = message;
        //                     // Limit nesting
        //                     for _ in 0..1024 {
        //                         match **current_message {
        //                             Message::Literal { .. } => {
        //                                 todo!()
        //                                 // return signature.verify(key, data.data());
        //                             }
        //                             Message::Compressed { reader } => {
        //                                 if decompress {
        //                                     let dec = reader.decompress()?;
        //                                     let msg = Message::from_bytes(dec)?;
        //                                     return msg.verify_internal(key, false);
        //                                 } else {
        //                                     bail!("Recursive decompression not allowed");
        //                                 }
        //                             }
        //                             Message::Encrypted { .. } => {
        //                                 todo!()
        //                                 // let data = message.to_bytes()?;
        //                                 // return signature.verify(key, &data[..]);
        //                             }
        //                             Message::Signed { ref message, .. } => {
        //                                 let Some(message) = message else {
        //                                     unimplemented_err!("no message, what to do?");
        //                                 };
        //                                 current_message = message;
        //                             }
        //                         }
        //                     }
        //                     bail!("More than 1024 nested signed messages are not supported");
        //                 }
        //                 Message::Compressed { reader } => {
        //                     debug!("verifying compressed message");
        //                     if decompress {
        //                         let dec = reader.decompress()?;
        //                         let msg = Message::from_bytes(dec)?;
        //                         msg.verify_internal(key, false)
        //                     } else {
        //                         bail!("Recursive decompression not allowed");
        //                     }
        //                 }
        //                 Message::Encrypted { .. } => {
        //                     debug!("verifying encrypted message");
        //                     // let data = message.to_bytes()?;
        //                     // signature.verify(key, &data[..])
        //                     todo!()
        //                 }
        //             }
        //         } else {
        //             unimplemented_err!("no message, what to do?");
        //         }
        //     }
        //     Message::Compressed { reader } => {
        //         debug!("verifying compressed message");
        //         if decompress {
        //             let msg = Message::from_bytes(reader.decompress()?)?;
        //             msg.verify_internal(key, false)
        //         } else {
        //             bail!("Recursive decompression not allowed");
        //         }
        //     }
        //     // We don't know how to verify a signature for other Message types, and shouldn't return Ok
        //     _ => unsupported_err!("Unexpected message format: {self:?}"),
        // }
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt(
        self,
        key_pws: &[Password],
        keys: &[&SignedSecretKey],
    ) -> Result<(Message<'a>, Vec<KeyId>)> {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => message.decrypt(key_pws, keys),
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
                            Ok((ek.key_id(), session_key))
                        } else if let Some(ek) = encoding_subkey {
                            let values = pkesk.values()?;
                            let session_key = ek.unlock(key_pw, |pub_params, priv_key| {
                                priv_key.decrypt(pub_params, values, typ, &ek.public_key())
                            })?;
                            Ok((ek.key_id(), session_key))
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
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => message.decrypt_with_password(msg_pw),
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

    /// Check if this message is a signature, that was signed with a one pass signature.
    pub fn is_one_pass_signed(&self) -> bool {
        match self {
            Message::Signed {
                one_pass_signature, ..
            } => one_pass_signature.is_some(),
            _ => false,
        }
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
        todo!()
    }

    pub fn packet_header(&self) -> PacketHeader {
        todo!()
    }

    /// Consumes the reader and reads into a vec.
    pub fn as_data_vec(&mut self) -> Vec<u8> {
        todo!()
    }

    /// Consumes the reader and reads into a string.
    pub fn as_data_string(&mut self) -> Result<String> {
        todo!()
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
