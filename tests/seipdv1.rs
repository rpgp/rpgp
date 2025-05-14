use chacha20::ChaCha8Rng;
use pgp::{
    composed::{Edata, Message, MessageBuilder, PlainSessionKey, RawSessionKey},
    crypto::sym::SymmetricKeyAlgorithm,
    packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig},
};
use rand::{CryptoRng, Rng, SeedableRng};

const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

fn make_seipdv1_msg<RAND>(mut rng: RAND) -> Vec<u8>
where
    RAND: CryptoRng + Rng,
{
    let input_data = b"hello world".repeat(1024);

    eprintln!("input len: {}", input_data.len());

    let raw = random_session_key(&mut rng);

    eprintln!("encrypting to session key: {:02x?}", raw.as_ref());
    eprintln!();

    let mut builder =
        MessageBuilder::from_bytes("plaintext.txt", input_data).seipd_v1(&mut rng, SYM_ALG);
    builder.set_session_key(raw).expect("ok");

    let mut encrypted_data = Vec::new();
    builder
        .to_writer(&mut rng, &mut encrypted_data)
        .expect("ok");

    encrypted_data
}

fn random_session_key<RAND>(mut rng: RAND) -> RawSessionKey
where
    RAND: CryptoRng + Rng,
{
    let mut raw = vec![0u8; SYM_ALG.key_size()];
    rng.fill_bytes(&mut raw);

    raw.into()
}

/// Try to decrypt SEIPDv1 encrypted data with a series of random (i.e. wrong) session keys.
/// This should not lead to successful decryption.
#[test]
pub fn mdc_test() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);

    // Produce an encrypted message, once
    let encrypted_data = make_seipdv1_msg(&mut rng);

    // Attempt decryption of this message with a series of (wrong) session keys
    for _ in 0..1024 {
        let encrypted = Message::from_bytes(&*encrypted_data).expect("ok");

        // Assert that the message is v1 SEIPD encrypted
        let Message::Encrypted {
            edata: Edata::SymEncryptedProtectedData { reader },
            ..
        } = &encrypted
        else {
            panic!("Should be SymEncryptedProtectedData")
        };
        assert!(matches!(
            reader.config(),
            ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1)
        ));

        // Try to decrypt with a random session key
        let raw = random_session_key(&mut rng);

        let sk = PlainSessionKey::V3_4 {
            key: raw.clone(),
            sym_alg: SYM_ALG,
        };

        let res = encrypted.decrypt_with_session_key(sk.clone());

        // We haven't read until the end of the stream yet
        if let Ok(mut decrypted) = res {
            // read to the end of the stream
            let plain = decrypted.as_data_vec();

            if let Ok(data) = plain {
                eprintln!(
                    "Decrypted len: {}, session key: {:02x?}",
                    data.len(),
                    raw.as_ref()
                );

                panic!("No MDC error!");
            }
        }
    }
}
