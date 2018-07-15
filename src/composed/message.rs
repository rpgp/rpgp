use std::boxed::Box;

use openssl::rsa::Padding;

use composed::key::PrivateKey;
use errors::Result;
use packet::types::key::PrivateKeyRepr;
use packet::types::Packet;

/// A PGP message
#[derive(Debug)]
pub enum Message {
    Literal(Packet),
    Compressed(Packet),
    Signed {
        /// nested message
        message: Option<Box<Message>>,
        /// for signature packets that contain a one pass message
        one_pass_signed_message: Option<OnePassSignedMessage>,
        // actual signature
        signature: Option<Packet>,
    },
    Encrypted {
        esk: Vec<Packet>,
        edata: Vec<Packet>,
    },
}

#[derive(Debug)]
pub struct OnePassSignedMessage {
    pub one_pass_signature: Packet,
    pub message: Option<Box<Message>>,
    pub signature: Option<Packet>,
}

impl Message {
    /// Decrypt the message using the given password and key.
    // TODO: allow for multiple keys to be passed in
    pub fn decrypt<'a, F, G>(&self, msg_pw: F, key_pw: G, key: &PrivateKey) -> Result<Vec<u8>>
    where
        F: FnOnce() -> String,
        G: FnOnce() -> String,
    {
        match self {
            Message::Compressed(packet) => Ok(packet.body.clone()),
            Message::Literal(packet) => Ok(packet.body.clone()),
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(msg_pw, key_pw, key),
                None => Ok(Vec::new()),
            },
            Message::Encrypted { esk, edata } => {
                key.unlock(key_pw, |priv_key| match priv_key {
                    PrivateKeyRepr::RSA(priv_key) => {
                        for packet in esk {
                            let mut out = vec![];
                            priv_key.private_decrypt(
                                packet.body.as_slice(),
                                out.as_mut_slice(),
                                Padding::PKCS1,
                            )?;
                            println!("res: {:?}", out);
                        }
                        Ok(())
                    }
                    PrivateKeyRepr::DSA(_) => unimplemented!("dsa"),
                    PrivateKeyRepr::ECDSA(priv_key) => {
                        for packet in esk {
                            println!("esk: {:?}", packet);
                        }
                        println!("{:?}", key.primary_key);
                        Ok(())
                    }
                })?;

                Ok(Vec::new())
            }
        }
    }

    /// Check if this message is a signature, that was signed with a one pass signature.
    pub fn is_one_pass_signed(&self) -> bool {
        match self {
            Message::Signed {
                one_pass_signed_message,
                ..
            } => one_pass_signed_message.is_some(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glob::glob;
    use serde_json;
    use std::fs::File;

    use composed::key::{PrivateKey, PublicKey};
    use composed::Deserializable;

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Testcase {
        typ: Option<String>,
        decrypt_key: String,
        passphrase: String,
        verify_key: Option<String>,
        filename: Option<String>,
        timestamp: Option<u64>,
        textcontent: Option<String>,
    }

    #[test]
    fn test_parse_pgp_messages() {
        let base_path = "./tests/opengpg-interop/testcases/messages";
        for entry in glob("./tests/opengpg-interop/testcases/messages/gnu*.json").unwrap() {
            let entry = entry.unwrap();
            let mut file = File::open(&entry).unwrap();

            let details: Testcase = serde_json::from_reader(&mut file).unwrap();
            println!("{:?}: {:?}", entry, details);

            let mut decrypt_key_file =
                File::open(format!("{}/{}", base_path, details.decrypt_key)).unwrap();
            let decrypt_key = PrivateKey::from_armor_single(&mut decrypt_key_file).unwrap();
            println!("decrypt key: {:?}", decrypt_key);

            if let Some(verify_key_str) = details.verify_key.clone() {
                let mut verify_key_file =
                    File::open(format!("{}/{}", base_path, verify_key_str)).unwrap();
                let verify_key = PublicKey::from_armor_single(&mut verify_key_file).unwrap();
                println!("verify key: {:?}", verify_key);
            }

            let file_name = entry.to_str().unwrap().replace(".json", ".asc");
            let mut cipher_file = File::open(file_name).unwrap();

            let message = Message::from_armor_single(&mut cipher_file).unwrap();
            let decrypted = message
                .decrypt(
                    || details.passphrase.clone(),
                    || "".to_string(),
                    &decrypt_key,
                )
                .unwrap();
            assert_eq!(
                ::std::str::from_utf8(&decrypted).unwrap(),
                details.textcontent.unwrap_or_else(|| "".to_string())
            );
        }
    }
}
