use std::boxed::Box;
use std::io::Cursor;

use num_traits::FromPrimitive;

use composed::message::types::{Edata, Message};
use composed::shared::Deserializable;
use crypto::{checksum, ecdh, rsa, SymmetricKeyAlgorithm};
use errors::Result;
use packet::SymKeyEncryptedSessionKey;
use types::{KeyTrait, SecretKeyRepr, SecretKeyTrait, Tag};

pub fn decrypt_session_key<F>(
    locked_key: &(impl SecretKeyTrait + KeyTrait),
    key_pw: F,
    mpis: &[Vec<u8>],
) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)>
where
    F: FnOnce() -> String,
{
    info!("decrypting session key");

    let mut key: Vec<u8> = Vec::new();
    let mut alg: Option<SymmetricKeyAlgorithm> = None;
    locked_key.unlock(key_pw, |priv_key| {
        let decrypted_key = match *priv_key {
            SecretKeyRepr::RSA(ref priv_key) => {
                rsa::decrypt(priv_key, mpis, &locked_key.fingerprint())?
            }
            SecretKeyRepr::DSA(_) => bail!("DSA is only used for signing"),
            SecretKeyRepr::ECDSA => bail!("ECDSA is only used for signing"),
            SecretKeyRepr::ECDH(ref priv_key) => {
                ecdh::decrypt(priv_key, mpis, &locked_key.fingerprint())?
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

pub fn decrypt_session_key_with_password<F>(
    packet: &SymKeyEncryptedSessionKey,
    msg_pw: F,
) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)>
where
    F: FnOnce() -> String,
{
    info!("decrypting session key");

    let key = packet
        .s2k()
        .derive_key(&msg_pw(), packet.sym_algorithm().key_size())?;

    match packet.encrypted_key() {
        Some(ref encrypted_key) => {
            let mut decrypted_key = encrypted_key.to_vec();
            // packet.sym_algorithm().decrypt(&key, &mut decrypted_key)?;
            let iv = vec![0u8; packet.sym_algorithm().block_size()];
            packet
                .sym_algorithm()
                .decrypt_with_iv_regular(&key, &iv, &mut decrypted_key)?;

            let alg = SymmetricKeyAlgorithm::from_u8(decrypted_key[0])
                .ok_or_else(|| format_err!("invalid symmetric key algorithm"))?;

            Ok((decrypted_key[1..].to_vec(), alg))
        }
        None => Ok((key, packet.sym_algorithm())),
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
