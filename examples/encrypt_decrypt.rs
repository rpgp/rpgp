use std::fs;

use pgp::{
    composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey},
    crypto::sym::SymmetricKeyAlgorithm,
    types::{CompressionAlgorithm, PublicKeyTrait},
};
use rand::thread_rng;

fn main() {
    let encrypted = {
        let msg = b"Secret message";
        let public_key = read_public_key(&fs::read("key.pub").unwrap());
        encrypt(&public_key, msg)
    };
    let secret_key = read_secret_key(&fs::read("key.priv").unwrap());
    let decrypted = decrypt(&secret_key, &encrypted);
    println!("{}", String::from_utf8_lossy(&decrypted));
}

fn unpack_msg(mut msg: Message) -> Vec<u8> {
    while msg.is_compressed() {
        msg = msg.decompress().unwrap();
    }
    msg.as_data_vec().unwrap()
}

fn encrypt(spk: &SignedPublicKey, msg: &[u8]) -> Vec<u8> {
    // Seacrhing for encryption subkey
    for sub in spk.public_subkeys.iter() {
        if sub.is_encryption_key() {
            let mut builder = MessageBuilder::from_bytes("", msg.to_vec())
                .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
            builder.compression(CompressionAlgorithm::ZIP);
            builder.encrypt_to_key(thread_rng(), &sub).unwrap();
            return builder.to_vec(thread_rng()).unwrap();
        }
    }
    panic!("Encryption key not found");
}

fn decrypt(ssk: &SignedSecretKey, msg: &[u8]) -> Vec<u8> {
    unpack_msg(
        Message::from_bytes(&msg[..])
            .unwrap()
            .decrypt(&"".into(), &ssk)
            .unwrap(),
    )
}

/// Simple helper funtion to read secret key from both armor and binary formats
pub fn read_secret_key(input: &[u8]) -> SignedSecretKey {
    // Try to interpret as UTF‑8 text first
    if let Ok(s) = std::str::from_utf8(&input) {
        let (key, _headers) = SignedSecretKey::from_string(s).unwrap();
        key.verify().unwrap();
        return key;
    }
    // Otherwise assume raw-binary
    let key = SignedSecretKey::from_bytes(input).unwrap();
    key.verify().unwrap();
    key
}

/// Simple helper funtion to read public key from both armor and binary formats
pub fn read_public_key(input: &[u8]) -> SignedPublicKey {
    // Try to interpret as UTF‑8 text first
    if let Ok(s) = std::str::from_utf8(&input) {
        let (key, _headers) = SignedPublicKey::from_string(s).unwrap();
        key.verify().unwrap();
        return key;
    }
    // Otherwise assume raw-binary
    let key = SignedPublicKey::from_bytes(input).unwrap();
    key.verify().unwrap();
    key
}
