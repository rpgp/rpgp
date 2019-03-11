use std::boxed::Box;
use std::collections::BTreeMap;
use std::io;

use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::Compression;
use rand::{CryptoRng, Rng};
use try_from::TryFrom;

use armor;
use composed::message::decrypt::*;
use composed::shared::Deserializable;
use composed::signed_key::SignedSecretKey;
use crypto::SymmetricKeyAlgorithm;
use errors::{Error, Result};
use packet::{
    write_packet, CompressedData, LiteralData, OnePassSignature, Packet,
    PublicKeyEncryptedSessionKey, Signature, SymEncryptedData, SymEncryptedProtectedData,
    SymKeyEncryptedSessionKey,
};
use ser::Serialize;
use types::{CompressionAlgorithm, KeyId, KeyTrait, PublicKeyTrait, StringToKey, Tag};

/// A PGP message
/// https://tools.ietf.org/html/rfc4880.html#section-11.3
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
        edata: Vec<Edata>,
    },
}

/// Encrypte Session Key
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
    type Err = Error;

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
    type Err = Error;

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
            Edata::SymEncryptedProtectedData(d) => d.data(),
        }
    }

    pub fn tag(&self) -> Tag {
        match self {
            Edata::SymEncryptedData(_) => Tag::SymEncryptedData,
            Edata::SymEncryptedProtectedData(_) => Tag::SymEncryptedProtectedData,
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
                for e in edata {
                    e.to_writer(writer)?;
                }

                Ok(())
            }
        }
    }
}

impl Message {
    pub fn new_literal(file_name: &str, data: &str) -> Self {
        Message::Literal(LiteralData::from_str(file_name, data))
    }

    pub fn compress(self, alg: CompressionAlgorithm) -> Result<Self> {
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
            CompressionAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
        };

        Ok(Message::Compressed(CompressedData::from_compressed(
            alg, data,
        )))
    }

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
        // TODO: Investigate exact usage of various integrity packets and add them.

        // 1. Generate a session key.
        let mut session_key = vec![0u8; alg.key_size()];
        rng.fill_bytes(&mut session_key);

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
        let data = self.to_bytes()?;

        let edata = vec![Edata::SymEncryptedProtectedData(
            SymEncryptedProtectedData::from_plain(alg, &session_key, &data)?,
        )];

        Ok(Message::Encrypted { esk, edata })
    }

    /// Encrytp the message using the given password.
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
        // TODO: Investigate exact usage of various integrity packets and add them.

        // 1. Generate a session key.
        let mut session_key = vec![0u8; alg.key_size()];
        rng.fill_bytes(&mut session_key);

        // 2. Encrypt (sym) the session key using the provided password.
        // TODO: handle version 5
        let skesk = Esk::SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey::from_session_key(
            rng,
            msg_pw,
            &session_key,
            s2k,
            alg,
        )?);

        // 3. Encrypt (sym) the data using the session key.
        let data = self.to_bytes()?;

        let edata = vec![Edata::SymEncryptedProtectedData(
            SymEncryptedProtectedData::from_plain(alg, &session_key, &data)?,
        )];

        Ok(Message::Encrypted {
            esk: vec![skesk],
            edata,
        })
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        match self {
            Message::Signed {
                signature, message, ..
            } => {
                if let Some(message) = message {
                    match **message {
                        Message::Literal(ref data) => signature.verify(key, data.data()),
                        _ => unimplemented_err!("verify for {:?}", *message),
                    }
                } else {
                    unimplemented_err!("no message, what to do?");
                }
            }
            Message::Compressed(data) => {
                let msg = Message::from_bytes(data.decompress()?)?;
                msg.verify(key)
            }
            // Nothing to do for others.
            // TODO: should this return an error?
            _ => Ok(()),
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
    pub fn decrypt<'a, F, G>(
        &'a self,
        msg_pw: F, // TODO: remove
        key_pw: G,
        keys: &[&SignedSecretKey],
    ) -> Result<(MessageDecrypter<'a>, Vec<KeyId>)>
    where
        F: FnOnce() -> String + Clone,
        G: FnOnce() -> String + Clone,
    {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(msg_pw, key_pw, keys),
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
                            info!("esk packet: {:?}", esk_packet);
                            info!("{:?}", key.key_id());
                            info!(
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
                                encoding_subkey = key.secret_subkeys.iter().find_map(|subkey| {
                                    if &subkey.key_id() == esk_packet.id() {
                                        Some(subkey)
                                    } else {
                                        None
                                    }
                                });
                            }

                            if encoding_key.is_some() || encoding_subkey.is_some() {
                                packet = Some(esk_packet);
                                break;
                            }
                        }

                        if let Some(packet) = packet {
                            Some((packet, encoding_key, encoding_subkey))
                        } else {
                            None
                        }
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
                let (session_key, alg) = {
                    let k0 = &session_keys[0].1;
                    if !session_keys.iter().skip(1).all(|(_, k)| k0 == k) {
                        bail!("found inconsistent session keys, possible message corruption");
                    }

                    // TODO: avoid cloning
                    (k0.0.clone(), k0.1)
                };

                let ids = session_keys.into_iter().map(|(k, _)| k).collect();

                Ok((MessageDecrypter::new(session_key, alg, edata), ids))
            }
        }
    }

    /// Decrypt the message using the given key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt_with_password<'a, F>(&'a self, msg_pw: F) -> Result<MessageDecrypter<'a>>
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

                let (session_key, alg) =
                    decrypt_session_key_with_password(&skesk.expect("checked above"), msg_pw)?;

                Ok(MessageDecrypter::new(session_key, alg, edata))
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
            Message::Signed { message, .. } => {
                if let Some(msg) = message {
                    msg.is_literal()
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub fn get_literal(&self) -> Option<&LiteralData> {
        match self {
            Message::Literal(ref data) => Some(data),
            Message::Signed { message, .. } => {
                if let Some(msg) = message {
                    msg.get_literal()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Returns the underlying content and `None` if the message is encrypted.
    pub fn get_content(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Message::Literal(ref data) => Ok(Some(data.data().to_vec())),
            Message::Signed { message, .. } => Ok(message
                .as_ref()
                .and_then(|m| m.get_literal())
                .map(|l| l.data().to_vec())),
            Message::Compressed(data) => {
                let msg = Message::from_bytes(data.decompress()?)?;
                msg.get_content()
            }
            Message::Encrypted { .. } => Ok(None),
        }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        headers: Option<&BTreeMap<String, String>>,
    ) -> Result<()> {
        armor::write(self, armor::BlockType::Message, writer, headers)
    }

    pub fn to_armored_bytes(&self, headers: Option<&BTreeMap<String, String>>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, headers)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, headers: Option<&BTreeMap<String, String>>) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes(headers)?)?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use serde_json;
    use std::fs;
    use std::fs::File;
    use std::io::{Cursor, Read};

    use composed::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
    use crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
    use types::{CompressionAlgorithm, SecretKeyTrait};

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Testcase {
        typ: Option<String>,
        decrypt_key: String,
        passphrase: String,
        verify_key: Option<String>,
        filename: Option<String>,
        timestamp: Option<u64>,
        textcontent: Option<String>,
        keyid: Option<String>,
    }

    fn test_parse_msg(entry: &str, base_path: &str, is_normalized: bool) {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        // TODO: verify filename
        let n = format!("{}/{}", base_path, entry);
        let mut file = File::open(&n).unwrap_or_else(|_| panic!("no file: {}", &n));

        let details: Testcase = serde_json::from_reader(&mut file).unwrap();
        info!(
            "Testcase: {}",
            serde_json::to_string_pretty(&details).unwrap()
        );

        let mut decrypt_key_file =
            File::open(format!("{}/{}", base_path, details.decrypt_key)).unwrap();
        let (decrypt_key, _headers) = SignedSecretKey::from_armor_single(&mut decrypt_key_file)
            .expect("failed to read decryption key");
        decrypt_key.verify().expect("invalid decryption key");

        let decrypt_id = hex::encode(&decrypt_key.key_id());

        info!("decrypt key (ID={})", &decrypt_id);
        if let Some(id) = &details.keyid {
            assert_eq!(id, &decrypt_id, "invalid keyid");
        }

        let verify_key = if let Some(verify_key_str) = details.verify_key.clone() {
            let mut verify_key_file =
                File::open(format!("{}/{}", base_path, verify_key_str)).unwrap();
            let (verify_key, _headers) = SignedPublicKey::from_armor_single(&mut verify_key_file)
                .expect("failed to read verification key");
            verify_key.verify().expect("invalid verification key");

            let verify_id = hex::encode(&verify_key.key_id());
            info!("verify key (ID={})", &verify_id);
            Some(verify_key)
        } else {
            None
        };

        let file_name = entry.replace(".json", ".asc");
        let cipher_file_path = format!("{}/{}", base_path, file_name);
        let mut cipher_file = File::open(&cipher_file_path).unwrap();

        let (message, headers) =
            Message::from_armor_single(&mut cipher_file).expect("failed to parse message");
        info!("message: {:?}", &message);

        match &message {
            Message::Encrypted { .. } => {
                let (mut decrypter, ids) = message
                    .decrypt(
                        || "".to_string(),
                        || details.passphrase.clone(),
                        &[&decrypt_key],
                    )
                    .expect("failed to init decryption");
                assert_eq!(ids.len(), 1);

                let decrypted = decrypter
                    .next()
                    .expect("no message")
                    .expect("message decryption failed");

                if let Some(verify_key) = verify_key {
                    decrypted
                        .verify(&verify_key.primary_key)
                        .expect("message verification failed");
                }

                // serialize and check we get the same thing
                let serialized = decrypted.to_armored_bytes(None).unwrap();

                // and parse them again
                let (decrypted2, _headers) = Message::from_armor_single(Cursor::new(&serialized))
                    .expect("failed to parse round2");
                assert_eq!(decrypted, decrypted2);

                let raw = match decrypted {
                    Message::Literal(data) => data,
                    Message::Compressed(data) => {
                        let m = Message::from_bytes(data.decompress().unwrap()).unwrap();

                        // serialize and check we get the same thing
                        let serialized = m.to_armored_bytes(None).unwrap();

                        // and parse them again
                        let (m2, _headers) = Message::from_armor_single(Cursor::new(&serialized))
                            .expect("failed to parse round3");
                        assert_eq!(m, m2);

                        m.get_literal().unwrap().clone()
                    }
                    _ => panic!("unexpected message type: {:?}", decrypted),
                };

                assert_eq!(
                    ::std::str::from_utf8(raw.data()).unwrap(),
                    details.textcontent.unwrap_or_else(|| "".to_string())
                );
            }
            Message::Signed { signature, .. } => {
                println!("signature: {:?}", signature);
            }
            _ => {
                // TODO: some other checks?
                panic!("this test should not have anything else?");
            }
        }

        // serialize and check we get the same thing
        let serialized = message.to_armored_string(Some(&headers)).unwrap();

        if is_normalized {
            let mut cipher_file = File::open(&cipher_file_path).unwrap();
            let mut expected_bytes = String::new();
            cipher_file.read_to_string(&mut expected_bytes).unwrap();
            assert_eq!(serialized, expected_bytes);
        }

        // and parse them again
        let (message2, headers2) =
            Message::from_armor_single(Cursor::new(&serialized)).expect("failed to parse round2");
        assert_eq!(headers, headers2);
        assert_eq!(message, message2);
    }

    macro_rules! msg_test {
        ($name:ident, $pos:expr, $normalized:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(
                    &format!("{}.json", $pos),
                    "./tests/opengpg-interop/testcases/messages",
                    $normalized,
                );
            }
        };
    }

    // RSA
    msg_test!(msg_gnupg_v1_001, "gnupg-v1-001", false);
    // Elgamal
    // msg_test!(msg_gnupg_v1_002, "gnupg-v1-002", true);
    // RSA
    msg_test!(msg_gnupg_v1_003, "gnupg-v1-003", false);

    msg_test!(msg_gnupg_v1_4_11_001, "gnupg-v1-4-11-001", true);
    msg_test!(msg_gnupg_v1_4_11_002, "gnupg-v1-4-11-002", false);
    msg_test!(msg_gnupg_v1_4_11_003, "gnupg-v1-4-11-003", true);
    msg_test!(msg_gnupg_v1_4_11_004, "gnupg-v1-4-11-004", true);
    // blowfish
    // msg_test!(msg_gnupg_v1_4_11_005, "gnupg-v1-4-11-005", true);
    msg_test!(msg_gnupg_v1_4_11_006, "gnupg-v1-4-11-006", false);
    msg_test!(msg_gnupg_v2_0_17_001, "gnupg-v2-0-17-001", true);
    msg_test!(msg_gnupg_v2_0_17_002, "gnupg-v2-0-17-002", false);
    msg_test!(msg_gnupg_v2_0_17_003, "gnupg-v2-0-17-003", true);
    msg_test!(msg_gnupg_v2_0_17_004, "gnupg-v2-0-17-004", true);
    // blowfish
    // msg_test!(msg_gnupg_v2_0_17_005, "gnupg-v2-0-17-005", true);
    msg_test!(msg_gnupg_v2_0_17_006, "gnupg-v2-0-17-006", true);
    // parsing error
    // ECDH key - nist p256
    // msg_test!(msg_gnupg_v2_1_5_001, "gnupg-v2-1-5-001", true);

    // parsing error
    // ECDH key - nist p384
    // msg_test!(msg_gnupg_v2_1_5_002, "gnupg-v2-1-5-002", true);
    // parsing error
    // ECDH key - nist p512
    // msg_test!(msg_gnupg_v2_1_5_003, "gnupg-v2-1-5-003", true);

    msg_test!(msg_gnupg_v2_10_001, "gnupg-v2-10-001", true);
    msg_test!(msg_gnupg_v2_10_002, "gnupg-v2-10-002", true);
    msg_test!(msg_gnupg_v2_10_003, "gnupg-v2-10-003", true);
    msg_test!(msg_gnupg_v2_10_004, "gnupg-v2-10-004", false);
    msg_test!(msg_gnupg_v2_10_005, "gnupg-v2-10-005", true);
    // blowfish
    // msg_test!(msg_gnupg_v2_10_006, "gnupg-v2-10-006", true);
    msg_test!(msg_gnupg_v2_10_007, "gnupg-v2-10-007", true);

    // ECDH
    // msg_test!(msg_e2e_001, "e2e-001", true);
    // ECDH
    // msg_test!(msg_e2e_002, "e2e-001", true);

    msg_test!(msg_pgp_10_0_001, "pgp-10-0-001", false);
    msg_test!(msg_pgp_10_0_002, "pgp-10-0-002", false);
    msg_test!(msg_pgp_10_0_003, "pgp-10-0-003", false);
    msg_test!(msg_pgp_10_0_004, "pgp-10-0-004", false);
    msg_test!(msg_pgp_10_0_005, "pgp-10-0-005", false);
    msg_test!(msg_pgp_10_0_006, "pgp-10-0-006", false);
    // IDEA
    // msg_test!(msg_pgp_10_0_007, "pgp-10-0-007", true);

    // ECDH
    // msg_test!(msg_openkeychain_001, "openkeychain-001", true);

    msg_test!(msg_openpgp_001, "openpgp-001", false);

    macro_rules! msg_test_js {
        ($name:ident, $pos:expr, $normalized:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(&format!("{}.json", $pos), "./tests/openpgpjs", $normalized);
            }
        };
    }

    msg_test_js!(msg_openpgpjs_x25519, "x25519", true);

    #[test]
    fn msg_partial_body_len() {
        let mut msg_file = File::open("./tests/partial.asc").unwrap();
        Message::from_armor_single(&mut msg_file).expect("failed to parse message");
    }

    #[test]
    fn msg_regression_01() {
        let mut msg_file = File::open("./tests/regression-01.asc").unwrap();
        Message::from_armor_single(&mut msg_file).expect("failed to parse message");
    }

    #[test]
    fn msg_large_indeterminate_len() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let mut msg_file = File::open("./tests/indeterminated.asc").unwrap();
        let (message, _headers) =
            Message::from_armor_single(&mut msg_file).expect("failed to parse message");

        let mut key_file = File::open("./tests/openpgpjs/x25519.sec.asc").unwrap();
        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_single(&mut key_file).expect("failed to parse key");

        let decrypted = message
            .decrypt(|| "".to_string(), || "moon".to_string(), &[&decrypt_key])
            .expect("failed to decrypt message")
            .0
            .next()
            .expect("no mesage")
            .expect("message decryption failed");

        let raw = match decrypted {
            Message::Literal(data) => data,
            Message::Compressed(data) => {
                let m = Message::from_bytes(data.decompress().unwrap()).unwrap();

                m.get_literal().unwrap().clone()
            }
            _ => panic!("unexpected message type: {:?}", decrypted),
        };

        assert_eq!(
            ::std::str::from_utf8(raw.data()).unwrap(),
            "Content-Type: text/plain; charset=us-ascii
Autocrypt-Gossip: addr=deltabot@codespeak.net; keydata=
  xsDNBFur7GMBDACeGJhpeP4xGZCUQcjFj1pPSXjWeFlezAo5Jkw5VivJoJRByJxO2dzg9HtAIYcgg2
  WR6b57rx/v9CyU6Ev653j4DMLghoKdyC/kGm/44pi9At4hXtXzgfp6ixKNuJnMfRC3fe0G5oRQY40c
  1AdaPDpfYaKT+dlFQLZpFXr+Jz+Y8Br717NXAYJUUOAWnH0oRkI1EfdttwF7kki0gLB93BvVc2hmE5
  xMiWEUHV+OlyqYeIJEtopGiqRRAKKZXmwkiQktiUTB+SaixAReXJmJQ1LW6lzceV7eqPC+NIUplv0N
  fTI4YcFCAbZr1Jl1Wo70oEXOidrH4LEOGLKlj9z6FoPRnPu3PhpHbCE0emimADSnc17t5m935emnMk
  6Bo0zl6ODzaqAYti6TMxCOcYtL+ypERweaprgL3BqQF7au7abCGM1QuOWObInQRLkO+hoXbSTIUhBo
  Ount8oa/BVwoWcxQaupI45IvT3TvTfFrW52zyxKTbfrA3MEi0SwBB4ZK4t8AEQEAAc0YPGRlbHRhYm
  90QGNvZGVzcGVhay5uZXQ+wsD8BBMBCAAmBQJbq+xjBQkAAAAAAhkBAhsDBgsJBwMCAQYVCAkKCwIC
  FgICHgEACgkQouc5Q3Wnbc/I+Qv9EDxYA1buPKfN42OcIhCnnMfc/r4uCtXjJri+/gxHRjkpPMWW9o
  /sRMPWKiFV9UUYeDKkln1Eh4mdI/RdyO6Q47znsBcwJzyddZoFD6VeSi3+oRM1q1ykDlczJZ639mfO
  eVH+ebPGUX/3apMPSUlflphQ1PKJo6Nwm6/oTfi+XQWwdj8IhHh801XEdqUlizVAWNAsy50COI5a+F
  Kxslfz6I1ce5ezsHNUCtVw0YP6/+YaeIsv+nazB1038jgjpeVJz2Xt4svWTpkgFF/LLeEXgdcZnI8Z
  u+IWdPSzz434YAynr68VdTjJoc2B+YPfqP38lkqnPAqaavwq/5/NLwJ6WCyVa/HCEu7OiYVEkXC4JX
  ZD4xdejrWG9p4JVQcwUv1rewbVqBMQ30ZlsBMAmEOh4+wkML+U+00/9LlQEv2wsLZMQ1OQVjxfncGb
  /tsOOavm25jhQnytwyM2j3eItnNni93Echqa0Fb3vQIB5ZrRtFVx15LomgsNWPHJN/BSeGuBzsDNBF
  ur7GMBDADPo8r8T2sDHaJ7NnVxxh5+dc9jgQkKdMmAba+RyJ2k0w5G4zKYQ5IZ1LEK5hXMkJ8dOOPW
  lUxvMqD732C2AwllLden4ZZNnMG/sXBNJXFcIOHMjG+Q8SzJ1q5tOQsqXGZ3+MRR9mfvJ8KLfaWWyY
  +I2Ow5gCkrueo/mTkCnVjOzQltuqUi6aG0f8B44A5+S0EfA4tFF0b0zJgReH4DfhQV7g+nUgbCmb3w
  EdRnrXL01JkDw5Zjy1Fx9QYNYzXk1hzWZugU9pSrMw7Sx4Zox+wWVCYTKfBvuJVVgNUDqv+B7RejeP
  OnMm2bI+AG3DgAOTaeTLa0xOqYF3n7tegFJTLCXYG9wUO8M76jttAjb8J3l9D/wiM+F+UPQcBFdRYZ
  JySUITyakgt8BrKzhtTKj/7lPdMYp+jglFFvvspnCZ3OJt0fHc9r58fFIdpuF/Wb7kEQkemoAZev2t
  1ZIEhFQFDFwWzJA3ymiRLwV/51JeH41N9TvKbG+bSxybIGIjZ26ccAEQEAAcLA5QQYAQgADwUCW6vs
  YwUJAAAAAAIbDAAKCRCi5zlDdadtz9U0C/0f+DIxh2IKK64MyWsCmv7BHIHEETtrXwQtYL9edOqrd2
  ty3f+QZ0MDS6/9f0/h4BWNa2WOxpUlamilAW1q2+JvLwKwwm7RVSOfmpJ0fVJn+d6E2LW8iz7rELza
  +6/SIivXkBHxZK9ykMdk4k1QlT6dA32mHzR+O7qL42htifHlzU7RTZio29oF0wOC2MHX96qMFXKS6z
  4s/6syEdrV4OZsyGo+/IrQubahrDE7/vDEHU0ez2AzmZuptJ6P3XcbzvEN1qwvrWO11DE22aCj7Iuv
  OoWICXyPb0u5DjSeejj5YoJ9frBiOSN5a/2Np4EII/3BY16cKDMEcE8104vIVEhmjzUWEWRP+BfUQm
  wU1xKr4A8VD/4iJzTOJr8wmsmyUyfrBJ378AoJrw3buuaOMxGX58RkN7Nv0djnfnmpwr73hmLlw9sr
  BS0T8vAI6psuMcmu/Oh2MUfnExZdYryW+/zOYWnGeEOi0ZiP/0KEZ5ePlchn/DlE549gB2Ht+U97na
  I=
Autocrypt-Gossip: addr=holger@merlinux.eu; keydata=
  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
  1CvHBWNRmnPMaFMeSpgJ

test1
"
        );
    }

    #[test]
    fn test_compression_zlib() {
        let lit_msg = Message::new_literal("hello-zlib.txt", "hello world");

        let compressed_msg = lit_msg
            .clone()
            .compress(CompressionAlgorithm::ZLIB)
            .unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_compression_zip() {
        let lit_msg = Message::new_literal("hello-zip.txt", "hello world");

        let compressed_msg = lit_msg.clone().compress(CompressionAlgorithm::ZIP).unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_compression_uncompressed() {
        let lit_msg = Message::new_literal("hello.txt", "hello world");

        let compressed_msg = lit_msg
            .clone()
            .compress(CompressionAlgorithm::Uncompressed)
            .unwrap();
        let uncompressed_msg = compressed_msg.decompress().unwrap();

        assert_eq!(&lit_msg, &uncompressed_msg);
    }

    #[test]
    fn test_rsa_encryption() {
        let (skey, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap(),
        )
        .unwrap();

        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();
        let mut rng = thread_rng();

        let lit_msg = Message::new_literal("hello.txt", "hello world\n");
        let compressed_msg = lit_msg.compress(CompressionAlgorithm::ZLIB).unwrap();
        let encrypted = compressed_msg
            .encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
            .unwrap();

        let armored = encrypted.to_armored_bytes(None).unwrap();
        fs::write("./message-rsa.asc", &armored).unwrap();

        let parsed = Message::from_armor_single(Cursor::new(&armored)).unwrap().0;

        let decrypted = parsed
            .decrypt(|| "".into(), || "test".into(), &[&skey])
            .unwrap()
            .0
            .next()
            .unwrap()
            .unwrap();

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
        let encrypted = compressed_msg
            .encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pkey][..])
            .unwrap();

        let armored = encrypted.to_armored_bytes(None).unwrap();
        fs::write("./message-x25519.asc", &armored).unwrap();

        let parsed = Message::from_armor_single(Cursor::new(&armored)).unwrap().0;

        let decrypted = parsed
            .decrypt(|| "".into(), || "".into(), &[&skey])
            .unwrap()
            .0
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(compressed_msg, decrypted);
    }

    #[test]
    fn test_password_encryption() {
        use pretty_env_logger;
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

        let armored = encrypted.to_armored_bytes(None).unwrap();
        fs::write("./message-password.asc", &armored).unwrap();

        let parsed = Message::from_armor_single(Cursor::new(&armored)).unwrap().0;

        let decrypted = parsed
            .decrypt_with_password(|| "secret".into())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(compressed_msg, decrypted);
    }
}
