use std::boxed::Box;
use std::io::Cursor;

use num_traits::FromPrimitive;
use try_from::TryFrom;

use composed::key::PrivateKey;
use composed::shared::Deserializable;
use crypto::checksum;
use crypto::ecc::decrypt_ecdh;
use crypto::rsa::decrypt_rsa;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::{Error, Result};
use packet::{
    CompressedData, LiteralData, OnePassSignature, Packet, PublicKeyEncryptedSessionKey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey,
};
use types::{KeyId, KeyTrait, PublicKeyTrait, SecretKeyRepr, SecretKeyTrait, Tag};

/// A PGP message
/// https://tools.ietf.org/html/rfc4880.html#section-11.3
#[derive(Clone, Debug)]
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
#[derive(Debug, Clone)]
pub enum Esk {
    PublicKeyEncryptedSessionKey(PublicKeyEncryptedSessionKey),
    SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey),
}

// impl Serialize for Esk {
//     fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
//         match self {
//             Esk::PublicKeyEncryptedSessionKey(k) => k.to_writer(writer),
//             Esk::SymKeyEncryptedSessionKey(k) => k.to_writer(writer),
//         }
//     }
// }

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
#[derive(Debug, Clone)]
pub enum Edata {
    SymEncryptedData(SymEncryptedData),
    SymEncryptedProtectedData(SymEncryptedProtectedData),
}

// impl Serialize for Edata {
//     fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
//         match self {
//             Edata::SymEncryptedData(d) => d.to_writer(writer),
//             Edata::SymEncryptedProtectedData(d) => d.to_writer(writer),
//         }
//     }
// }

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

// impl Serialize for Message {
//     fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
//         match self {
//             Message::Literal(l) => l.to_writer(writer),
//             Message::Compressed(c) => c.to_writer(writer),
//             Message::Signed {
//                 message,
//                 one_pass_signature,
//                 signature,
//             } => {
//                 if let Some(ops) = one_pass_signature {
//                     ops.to_writer(writer)?;
//                 }
//                 if let Some(message) = message {
//                     (**message).to_writer(writer)?;
//                 }

//                 signature.to_writer(writer)
//             }
//             Message::Encrypted { esk, edata } => {
//                 for e in esk {
//                     e.to_writer(writer)?;
//                 }
//                 for e in edata {
//                     e.to_writer(writer)?;
//                 }

//                 Ok(())
//             }
//         }
//     }
// }

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
                let msg = Message::from_bytes(m.decompress())?;
                msg.verify(key)
            }
            // Nothing to do for others.
            // TODO: should this return an error?
            _ => Ok(()),
        }
    }

    /// Decrypt the message using the given password and key.
    // TODO: allow for multiple keys to be passed in
    pub fn decrypt<'a, F, G>(
        &'a self,
        msg_pw: F,
        key_pw: G,
        key: &PrivateKey,
    ) -> Result<MessageDecrypter<'a>>
    where
        F: FnOnce() -> String,
        G: FnOnce() -> String,
    {
        match self {
            Message::Compressed(_) | Message::Literal(_) => {
                bail!("not encrypted");
            }
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(msg_pw, key_pw, key),
                None => bail!("not encrypted"),
            },
            Message::Encrypted { esk, edata } => {
                // search for a packet with a key id that we have and that key
                let mut packet = None;
                let mut encoding_key = None;
                let mut encoding_subkey = None;

                for esk_packet in esk {
                    info!("esk packet: {:?}", esk_packet);
                    info!("{:?}", key.key_id());
                    info!(
                        "{:?}",
                        key.private_subkeys
                            .iter()
                            .map(|k| k.key_id())
                            .collect::<Vec<_>>()
                    );

                    // find the key with the matching key id

                    if &key
                        .primary_key
                        .key_id()
                        .ok_or_else(|| format_err!("missing key_id"))?
                        == esk_packet.id()
                    {
                        encoding_key = Some(&key.primary_key);
                    } else {
                        encoding_subkey = key.private_subkeys.iter().find_map(|subkey| {
                            if let Some(id) = subkey.key_id() {
                                if &id == esk_packet.id() {
                                    Some(subkey)
                                } else {
                                    None
                                }
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

                let packet = packet.ok_or_else(|| Error::MissingKey)?;

                if let Some(encoding_key) = encoding_key {
                    MessageDecrypter::new(encoding_key, key_pw, packet.mpis(), edata)
                } else if let Some(encoding_key) = encoding_subkey {
                    MessageDecrypter::new(encoding_key, key_pw, packet.mpis(), edata)
                } else {
                    Err(Error::MissingKey)
                }
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

    pub fn get_literal(&self) -> Option<&Message> {
        match self {
            Message::Literal(_) => Some(self),
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
    pub fn new<F>(
        locked_key: &(impl SecretKeyTrait + KeyTrait),
        key_pw: F,
        mpis: &'a [Vec<u8>],
        edata: &'a [Edata],
    ) -> Result<Self>
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
                SecretKeyRepr::DSA => unimplemented_err!("DSA"),
                SecretKeyRepr::ECDSA => unimplemented_err!("ECDSA"),
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

        Ok(MessageDecrypter {
            key,
            alg: alg.expect("failed to unlock"),
            edata,
            pos: 0,
            current_msgs: None,
        })
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

    use composed::key::{PrivateKey, PublicKey};
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
        let decrypt_key = PrivateKey::from_armor_single(&mut decrypt_key_file)
            .expect("failed to read decryption key");
        decrypt_key.verify().expect("invalid decryption key");

        let decrypt_id = hex::encode(decrypt_key.key_id().unwrap().to_vec());

        info!("decrypt key (ID={})", &decrypt_id);
        if let Some(id) = &details.keyid {
            assert_eq!(id, &decrypt_id, "invalid keyid");
        }

        let verify_key = if let Some(verify_key_str) = details.verify_key.clone() {
            let mut verify_key_file =
                File::open(format!("{}/{}", base_path, verify_key_str)).unwrap();
            let verify_key = PublicKey::from_armor_single(&mut verify_key_file)
                .expect("failed to read verification key");
            verify_key.verify().expect("invalid verification key");

            let verify_id = hex::encode(verify_key.key_id().unwrap().to_vec());
            info!("verify key (ID={})", &verify_id);
            Some(verify_key)
        } else {
            None
        };

        let file_name = entry.replace(".json", ".asc");
        let mut cipher_file = File::open(format!("{}/{}", base_path, file_name)).unwrap();

        let message =
            Message::from_armor_single(&mut cipher_file).expect("failed to parse message");
        info!("message: {:?}", message);

        match message {
            Message::Encrypted { .. } => {
                let decrypted = message
                    .decrypt(
                        || "".to_string(),
                        || details.passphrase.clone(),
                        &decrypt_key,
                    )
                    .expect("failed to decrypt message")
                    .next()
                    .expect("no mesage")
                    .expect("message decryption failed");

                if let Some(verify_key) = verify_key {
                    decrypted
                        .verify(&verify_key.primary_key)
                        .expect("message verification failed");
                }

                let raw = match decrypted {
                    Message::Literal(msg) => msg,
                    Message::Compressed(msg) => {
                        let m = Message::from_bytes(msg.decompress()).unwrap();

                        if let Message::Literal(msg) = m.get_literal().unwrap() {
                            msg.clone()
                        } else {
                            panic!("unexpected message type: {:?}", m)
                        }
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
            }
        }
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

    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v1_4_11_001, "gnupg-v1-4-11-001");
    msg_test!(msg_gnupg_v1_4_11_002, "gnupg-v1-4-11-002");
    msg_test!(msg_gnupg_v1_4_11_003, "gnupg-v1-4-11-003");
    msg_test!(msg_gnupg_v1_4_11_004, "gnupg-v1-4-11-004");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v1_4_11_005, "gnupg-v1-4-11-005");
    msg_test!(msg_gnupg_v1_4_11_006, "gnupg-v1-4-11-006");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_0_17_001, "gnupg-v2-0-17-001");
    msg_test!(msg_gnupg_v2_0_17_002, "gnupg-v2-0-17-002");
    msg_test!(msg_gnupg_v2_0_17_003, "gnupg-v2-0-17-003");
    msg_test!(msg_gnupg_v2_0_17_004, "gnupg-v2-0-17-004");
    // disabled because of blockciphers not updated
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
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_10_001, "gnupg-v2-10-001");
    msg_test!(msg_gnupg_v2_10_002, "gnupg-v2-10-002");
    msg_test!(msg_gnupg_v2_10_003, "gnupg-v2-10-003");
    msg_test!(msg_gnupg_v2_10_004, "gnupg-v2-10-004");
    msg_test!(msg_gnupg_v2_10_005, "gnupg-v2-10-005");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_10_006, "gnupg-v2-10-006");
    msg_test!(msg_gnupg_v2_10_007, "gnupg-v2-10-007");

    // ECDH
    // msg_test!(msg_e2e_001, "e2e-001");
    // ECDH
    // msg_test!(msg_e2e_002, "e2e-001");

    // disabled because of blockciphers not updated
    // msg_test!(msg_pgp_10_0_001, "pgp-10-0-001");
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
}
