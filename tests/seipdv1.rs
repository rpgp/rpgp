use aead::rand_core::RngCore;
use pgp::{
    composed::{Message, MessageBuilder, PlainSessionKey},
    crypto::sym::SymmetricKeyAlgorithm,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
pub fn mdc_test() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let input_data = b"hello world".repeat(1024);

    let mut raw = vec![0u8; 32];
    rng.fill_bytes(&mut raw);

    let mut builder = MessageBuilder::from_bytes("plaintext.txt", input_data)
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.set_session_key(raw.into()).expect("ok");

    let mut encrypted_data = Vec::new();
    builder
        .to_writer(&mut rng, &mut encrypted_data)
        .expect("ok");

    // Attempt decryption with a series of (wrong) session keys and observe the resulting errors
    for _ in 0..1024 {
        let encrypted = Message::from_bytes(&*encrypted_data).expect("ok");

        let mut raw = vec![0u8; 32];
        rng.fill_bytes(&mut raw);

        let sk = PlainSessionKey::V3_4 {
            key: raw.into(),
            sym_alg: SymmetricKeyAlgorithm::AES256,
        };

        let res = encrypted.decrypt_with_session_key(sk);

        eprintln!("res: {:?}", res);
    }
}
