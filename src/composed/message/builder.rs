#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use composed::{Deserializable, Message, SignedSecretKey};
    use crypto::SymmetricKeyAlgorithm;
    use types::{CompressionAlgorithm, SecretKeyTrait};

    use std::fs;
    use std::io::Cursor;

    #[test]
    fn test_rsa_encryption() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

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
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

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
}
