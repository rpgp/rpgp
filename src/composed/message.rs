use std::boxed::Box;

use byteorder::{BigEndian, ReadBytesExt};
use enum_primitive::FromPrimitive;
use openssl::rsa::Padding;

use composed::key::PrivateKey;
use composed::shared::Deserializable;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::{Error, Result};
use packet::tags::public_key_encrypted_session_key::PKESK;
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
        esk: Vec<PKESK>,
        edata: Vec<Packet>,
        protected: bool,
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
    pub fn decrypt<F, G>(&self, msg_pw: F, key_pw: G, key: &PrivateKey) -> Result<Vec<u8>>
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
            Message::Encrypted {
                esk,
                edata,
                protected,
            } => {
                println!("unlocked key! msg protected={}", protected);

                // search for a packet with a key id that we have and that key
                let mut packet = None;
                let mut encoding_key = None;
                let mut encoding_subkey = None;

                for esk_packet in esk {
                    println!("esk packet: {:?}", esk_packet);
                    println!("{:?}", key.key_id());
                    println!(
                        "{:?}",
                        key.subkeys.iter().map(|k| k.key_id()).collect::<Vec<_>>()
                    );

                    // find the key with the matching key id

                    if key.primary_key.key_id().expect("missing key_id") == esk_packet.id {
                        encoding_key = Some(&key.primary_key);
                    } else {
                        encoding_subkey = key.subkeys.iter().find(|subkey| {
                            subkey.key_id().expect("missing key_id") == esk_packet.id
                        });
                    }

                    if encoding_key.is_some() || encoding_subkey.is_some() {
                        packet = Some(esk_packet);
                        break;
                    }
                }

                if packet.is_none() {
                    return Err(Error::MissingKey);
                }

                let packet = packet.unwrap();

                let mut res: Vec<u8> = Vec::new();
                if let Some(encoding_key) = encoding_key {
                    println!(
                        "decrypting using key {}",
                        hex::encode(encoding_key.key_id().unwrap().to_vec())
                    );

                    encoding_key.unlock(key_pw, |priv_key| {
                        res = decrypt(priv_key, &packet.mpis, &edata, *protected)?;
                        Ok(())
                    })?;
                } else if let Some(encoding_key) = encoding_subkey {
                    println!(
                        "decrypting using subkey {}",
                        hex::encode(encoding_key.key_id().unwrap().to_vec())
                    );

                    let mut sym_key = vec![0u8; 8];
                    encoding_key.unlock(key_pw, |priv_key| {
                        res = decrypt(priv_key, &packet.mpis, &edata, *protected)?;
                        Ok(())
                    })?;
                    println!("symkey {:?}", sym_key);
                } else {
                    return Err(Error::MissingKey);
                }

                let mut res = Vec::new();

                // TODO: decrypt

                Ok(res)
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

fn decrypt(
    priv_key: &PrivateKeyRepr,
    mpis: &[Vec<u8>],
    edata: &[Packet],
    protected: bool,
) -> Result<Vec<u8>> {
    match priv_key {
        &PrivateKeyRepr::RSA(ref priv_key) => {
            // rsa consist of exactly one mpi
            let mpi = &mpis[0];
            println!("RSA m^e mod n: {}", hex::encode(mpi));
            let mut m = vec![0u8; mpi.len()];
            priv_key.private_decrypt(mpi, &mut m, Padding::PKCS1)?;
            println!("m: {}", hex::encode(&m));
            let alg = SymmetricKeyAlgorithm::from_u8(m[0]).unwrap();
            println!("alg: {:?}", alg);

            let key_size = alg.key_size();
            let key = &m[1..key_size + 1];
            let mut checksum = &m[key_size + 1..key_size + 3];

            // Then a two-octet checksum is appended, which is equal to the
            // sum of the preceding session key octets, not including the algorithm
            // identifier, modulo 65536.
            let checksum = checksum.read_u16::<BigEndian>()? as u32;
            let expected_checksum = key.iter().map(|v| *v as u32).sum::<u32>() & 0xffff;

            println!("key: {}\nchecksum: {}", hex::encode(&key), checksum);
            // TODO: proper error handling
            assert_eq!(checksum, expected_checksum, "wrong checksum");

            println!("decrypting {} packets", edata.len());
            for packet in edata {
                assert_eq!(packet.body[0], 1, "invalid packet version");

                let mut res = packet.body[1..].to_vec();
                println!("decrypting protected = {:?}", protected);
                let decrypted_packet = if protected {
                    alg.decrypt_protected(key, &mut res)?
                } else {
                    alg.decrypt(key, &mut res)?
                };
                println!("decoding message");
                let msg = Message::from_bytes_many(decrypted_packet)?;
                println!("msg: {:?}", msg);
            }
            Ok(Vec::new())
        }
        &PrivateKeyRepr::DSA(_) => unimplemented!("dsa"),
        &PrivateKeyRepr::ECDSA(ref priv_key) => Ok(Vec::new()),
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
            println!(
                "decrypt key (ID={}): {:?}",
                hex::encode(decrypt_key.key_id().unwrap().to_vec()),
                decrypt_key
            );

            if let Some(verify_key_str) = details.verify_key.clone() {
                let mut verify_key_file =
                    File::open(format!("{}/{}", base_path, verify_key_str)).unwrap();
                let verify_key = PublicKey::from_armor_single(&mut verify_key_file).unwrap();
                println!(
                    "verify key (ID={}): {:?}",
                    hex::encode(verify_key.key_id().unwrap().to_vec()),
                    verify_key
                );
            }

            let file_name = entry.to_str().unwrap().replace(".json", ".asc");
            let mut cipher_file = File::open(file_name).unwrap();

            let message = Message::from_armor_single(&mut cipher_file).unwrap();
            println!("message: {:?}", message);
            let decrypted = message
                .decrypt(
                    || "".to_string(),
                    || details.passphrase.clone(),
                    &decrypt_key,
                )
                .expect("failed to decrypt message");
            assert_eq!(
                ::std::str::from_utf8(&decrypted).unwrap(),
                details.textcontent.unwrap_or_else(|| "".to_string())
            );
        }
    }
}
