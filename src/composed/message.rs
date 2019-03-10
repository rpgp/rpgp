use std::boxed::Box;
use std::io::{self, Cursor};

use generic_array::typenum::U64;
use num_traits::FromPrimitive;
use try_from::TryFrom;

use composed::shared::Deserializable;
use composed::signed_key::SignedSecretKey;
use crypto::checksum;
use crypto::ecc::decrypt_ecdh;
use crypto::rsa::decrypt_rsa;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::{Error, Result};
use line_writer::{LineBreak, LineWriter};
use packet::{
    write_packet, CompressedData, LiteralData, OnePassSignature, Packet,
    PublicKeyEncryptedSessionKey, Signature, SymEncryptedData, SymEncryptedProtectedData,
    SymKeyEncryptedSessionKey,
};
use ser::Serialize;
use types::{KeyId, KeyTrait, PublicKeyTrait, SecretKeyRepr, SecretKeyTrait, Tag};

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
    pub fn id(&self) -> &KeyId {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.id(),
            Esk::SymKeyEncryptedSessionKey(k) => k.id(),
        }
    }

    pub fn mpis(&self) -> &[Vec<u8>] {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.mpis(),
            Esk::SymKeyEncryptedSessionKey(k) => k.mpis(),
        }
    }

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
            Message::Literal(l) => write_packet(writer, l),
            Message::Compressed(c) => write_packet(writer, c),
            Message::Signed {
                message,
                one_pass_signature,
                signature,
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
            Message::Encrypted { esk, edata } => {
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
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        match self {
            Message::Signed {
                signature, message, ..
            } => {
                if let Some(message) = message {
                    match **message {
                        Message::Literal(ref m) => signature.verify(key, m.data()),
                        _ => unimplemented_err!("verify for {:?}", *message),
                    }
                } else {
                    unimplemented_err!("no message, what to do?");
                }
            }
            Message::Compressed(m) => {
                let msg = Message::from_bytes(m.decompress()?)?;
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
            Message::Encrypted { esk, .. } => esk.iter().map(Esk::id).collect(),
            _ => Vec::new(),
        }
    }

    /// Decrypt the message using the given password and key.
    /// Returns a message decrypter, and a list of [KeyId]s that are valid recipients of this message.
    pub fn decrypt<'a, F, G>(
        &'a self,
        msg_pw: F,
        key_pw: G,
        keys: &[&SignedSecretKey],
    ) -> Result<(MessageDecrypter<'a>, Vec<KeyId>)>
    where
        F: FnOnce() -> String + Clone,
        G: FnOnce() -> String + Clone,
    {
        match self {
            Message::Compressed(_) | Message::Literal(_) => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(msg_pw, key_pw, keys),
                None => bail!("not encrypted"),
            },
            Message::Encrypted { esk, edata } => {
                let valid_keys = keys
                    .iter()
                    .filter_map(|key| {
                        // search for a packet with a key id that we have and that key.
                        let mut packet = None;
                        let mut encoding_key = None;
                        let mut encoding_subkey = None;

                        for esk_packet in esk {
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
                            warn!("failed to decrpty session_key for key: {:?}", err);
                            false
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;

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
            Message::Literal(_) => true,
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
            Message::Literal(ref msg) => Some(msg),
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
            Message::Literal(ref msg) => Ok(Some(msg.data().to_vec())),
            Message::Signed { message, .. } => Ok(message
                .as_ref()
                .and_then(|m| m.get_literal())
                .map(|l| l.data().to_vec())),
            Message::Compressed(m) => {
                let msg = Message::from_bytes(m.decompress()?)?;
                msg.get_content()
            }
            Message::Encrypted { .. } => Ok(None),
        }
    }

    pub fn to_armored_writer(&self, writer: &mut impl io::Write) -> Result<()> {
        writer.write_all(&b"-----BEGIN PGP MESSAGE-----\n"[..])?;

        // TODO: headers

        // write the base64 encoded content
        {
            let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
            let mut enc = base64::write::EncoderWriter::new(&mut line_wrapper, base64::STANDARD);
            self.to_writer(&mut enc)?;
        }
        // TODO: CRC24

        writer.write_all(&b"\n-----END PGP MESSAGE-----\n"[..])?;

        Ok(())
    }

    pub fn to_armored_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes()?)?.to_string())
    }
}

fn decrypt_session_key<F>(
    locked_key: &(impl SecretKeyTrait + KeyTrait),
    key_pw: F,
    mpis: &[Vec<u8>],
) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)>
where
    F: FnOnce() -> String,
{
    let mut key: Vec<u8> = Vec::new();
    let mut alg: Option<SymmetricKeyAlgorithm> = None;

    locked_key.unlock(key_pw, |priv_key| {
        let decrypted_key = match *priv_key {
            SecretKeyRepr::RSA(ref priv_key) => {
                decrypt_rsa(priv_key, mpis, &locked_key.fingerprint())?
            }
            SecretKeyRepr::DSA(_) => bail!("DSA is only used for signing"),
            SecretKeyRepr::ECDSA => bail!("ECDSA is only used for signing"),
            SecretKeyRepr::ECDH(ref priv_key) => {
                decrypt_ecdh(priv_key, mpis, &locked_key.fingerprint())?
            }
            SecretKeyRepr::EdDSA(_) => unimplemented_err!("EdDSA"),
        };
        let algorithm = SymmetricKeyAlgorithm::from_u8(decrypted_key[0])
            .ok_or_else(|| format_err!("invalid symmetric key algorithm"))?;
        alg = Some(algorithm);
        info!("alg: {:?}", alg);

        let (k, checksum) = match *priv_key {
            SecretKeyRepr::ECDH(_) => {
                let dec_len = decrypted_key.len();
                (
                    &decrypted_key[1..dec_len - 2],
                    &decrypted_key[dec_len - 2..],
                )
            }
            _ => {
                let key_size = algorithm.key_size();
                (
                    &decrypted_key[1..=key_size],
                    &decrypted_key[key_size + 1..key_size + 3],
                )
            }
        };

        key = k.to_vec();
        checksum::simple(checksum, k)?;

        Ok(())
    })?;

    Ok((key, alg.expect("failed to unlock")))
}

pub struct MessageDecrypter<'a> {
    key: Vec<u8>,
    alg: SymmetricKeyAlgorithm,
    edata: &'a [Edata],
    // position in the edata slice
    pos: usize,
    // the current msgs that are already decrypted
    current_msgs: Option<Box<dyn Iterator<Item = Result<Message>>>>,
}

impl<'a> MessageDecrypter<'a> {
    pub fn new(session_key: Vec<u8>, alg: SymmetricKeyAlgorithm, edata: &'a [Edata]) -> Self {
        MessageDecrypter {
            key: session_key,
            alg,
            edata,
            pos: 0,
            current_msgs: None,
        }
    }
}

impl<'a> Iterator for MessageDecrypter<'a> {
    type Item = Result<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.edata.len() && self.current_msgs.is_none() {
            return None;
        }

        if self.current_msgs.is_none() {
            // need to decrypt another packet
            let packet = &self.edata[self.pos];
            self.pos += 1;

            let mut res = packet.data()[..].to_vec();
            let protected = packet.tag() == Tag::SymEncryptedProtectedData;

            info!("decrypting protected = {:?}", protected);

            let decrypted_packet: &[u8] = if protected {
                err_opt!(self.alg.decrypt_protected(&self.key, &mut res))
            } else {
                err_opt!(self.alg.decrypt(&self.key, &mut res))
            };

            self.current_msgs = Some(Message::from_bytes_many(Cursor::new(
                decrypted_packet.to_vec(),
            )));
        };

        let mut msgs = self.current_msgs.take().expect("just checked");
        let next = msgs.next();
        self.current_msgs = Some(msgs);

        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::fs::File;

    use composed::signed_key::{SignedPublicKey, SignedSecretKey};
    use composed::Deserializable;

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

    fn test_parse_msg(entry: &str, base_path: &str) {
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
        let decrypt_key = SignedSecretKey::from_armor_single(&mut decrypt_key_file)
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
            let verify_key = SignedPublicKey::from_armor_single(&mut verify_key_file)
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

        let message =
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
                let serialized = decrypted.to_armored_bytes().unwrap();

                // and parse them again
                let decrypted2 = Message::from_armor_single(Cursor::new(&serialized))
                    .expect("failed to parse round2");
                assert_eq!(decrypted, decrypted2);

                let raw = match decrypted {
                    Message::Literal(msg) => msg,
                    Message::Compressed(msg) => {
                        let m = Message::from_bytes(msg.decompress().unwrap()).unwrap();

                        // serialize and check we get the same thing
                        let serialized = m.to_armored_bytes().unwrap();

                        // and parse them again
                        let m2 = Message::from_armor_single(Cursor::new(&serialized))
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
        let serialized = message.to_armored_bytes().unwrap();

        // let mut cipher_file = File::open(&cipher_file_path).unwrap();
        // let mut expected_bytes = String::new();
        // cipher_file.read_to_string(&mut expected_bytes).unwrap();
        // assert_eq!(serialized, expected_bytes);

        // and parse them again
        let message2 =
            Message::from_armor_single(Cursor::new(&serialized)).expect("failed to parse round2");
        assert_eq!(message, message2);
    }

    macro_rules! msg_test {
        ($name:ident, $pos:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(
                    &format!("{}.json", $pos),
                    "./tests/opengpg-interop/testcases/messages",
                );
            }
        };
    }

    // RSA
    msg_test!(msg_gnupg_v1_001, "gnupg-v1-001");
    // Elgamal
    // msg_test!(msg_gnupg_v1_002, "gnupg-v1-002");
    // RSA
    msg_test!(msg_gnupg_v1_003, "gnupg-v1-003");

    msg_test!(msg_gnupg_v1_4_11_001, "gnupg-v1-4-11-001");
    msg_test!(msg_gnupg_v1_4_11_002, "gnupg-v1-4-11-002");
    msg_test!(msg_gnupg_v1_4_11_003, "gnupg-v1-4-11-003");
    msg_test!(msg_gnupg_v1_4_11_004, "gnupg-v1-4-11-004");
    // blowfish
    // msg_test!(msg_gnupg_v1_4_11_005, "gnupg-v1-4-11-005");
    msg_test!(msg_gnupg_v1_4_11_006, "gnupg-v1-4-11-006");
    msg_test!(msg_gnupg_v2_0_17_001, "gnupg-v2-0-17-001");
    msg_test!(msg_gnupg_v2_0_17_002, "gnupg-v2-0-17-002");
    msg_test!(msg_gnupg_v2_0_17_003, "gnupg-v2-0-17-003");
    msg_test!(msg_gnupg_v2_0_17_004, "gnupg-v2-0-17-004");
    // blowfish
    // msg_test!(msg_gnupg_v2_0_17_005, "gnupg-v2-0-17-005");
    msg_test!(msg_gnupg_v2_0_17_006, "gnupg-v2-0-17-006");
    // parsing error
    // ECDH key - nist p256
    // msg_test!(msg_gnupg_v2_1_5_001, "gnupg-v2-1-5-001");
    // parsing error
    // ECDH key - nist p384
    // msg_test!(msg_gnupg_v2_1_5_002, "gnupg-v2-1-5-002");
    // parsing error
    // ECDH key - nist p512
    // msg_test!(msg_gnupg_v2_1_5_003, "gnupg-v2-1-5-003");

    msg_test!(msg_gnupg_v2_10_001, "gnupg-v2-10-001");
    msg_test!(msg_gnupg_v2_10_002, "gnupg-v2-10-002");
    msg_test!(msg_gnupg_v2_10_003, "gnupg-v2-10-003");
    msg_test!(msg_gnupg_v2_10_004, "gnupg-v2-10-004");
    msg_test!(msg_gnupg_v2_10_005, "gnupg-v2-10-005");
    // blowfish
    // msg_test!(msg_gnupg_v2_10_006, "gnupg-v2-10-006");
    msg_test!(msg_gnupg_v2_10_007, "gnupg-v2-10-007");

    // ECDH
    // msg_test!(msg_e2e_001, "e2e-001");
    // ECDH
    // msg_test!(msg_e2e_002, "e2e-001");

    msg_test!(msg_pgp_10_0_001, "pgp-10-0-001");
    msg_test!(msg_pgp_10_0_002, "pgp-10-0-002");
    msg_test!(msg_pgp_10_0_003, "pgp-10-0-003");
    msg_test!(msg_pgp_10_0_004, "pgp-10-0-004");
    msg_test!(msg_pgp_10_0_005, "pgp-10-0-005");
    msg_test!(msg_pgp_10_0_006, "pgp-10-0-006");
    // IDEA
    // msg_test!(msg_pgp_10_0_007, "pgp-10-0-007");

    // ECDH
    // msg_test!(msg_openkeychain_001, "openkeychain-001");

    msg_test!(msg_openpgp_001, "openpgp-001");

    macro_rules! msg_test_js {
        ($name:ident, $pos:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(&format!("{}.json", $pos), "./tests/openpgpjs");
            }
        };
    }

    msg_test_js!(msg_openpgpjs_x25519, "x25519");

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
        let message = Message::from_armor_single(&mut msg_file).expect("failed to parse message");

        let mut key_file = File::open("./tests/openpgpjs/x25519.sec.asc").unwrap();
        let decrypt_key =
            SignedSecretKey::from_armor_single(&mut key_file).expect("failed to parse key");

        let decrypted = message
            .decrypt(|| "".to_string(), || "moon".to_string(), &[&decrypt_key])
            .expect("failed to decrypt message")
            .0
            .next()
            .expect("no mesage")
            .expect("message decryption failed");

        let raw = match decrypted {
            Message::Literal(msg) => msg,
            Message::Compressed(msg) => {
                let m = Message::from_bytes(msg.decompress().unwrap()).unwrap();

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
}
