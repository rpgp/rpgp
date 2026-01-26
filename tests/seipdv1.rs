use pgp::{
    composed::{Edata, Message, MessageBuilder, PlainSessionKey, RawSessionKey},
    crypto::sym::SymmetricKeyAlgorithm,
    packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig},
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

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

/// Regression: garbage parsing as `Padding -> Signed { Encrypted }` must still check MDC.
#[test]
pub fn mdc_test_fast() {
    pretty_env_logger::try_init().ok();

    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let encrypted_data = make_seipdv1_msg(&mut rng);

    let bad_key: RawSessionKey = vec![
        0x1c, 0xab, 0x4b, 0x64, 0x2c, 0x12, 0xec, 0x86, 0x7b, 0x1f, 0xd9, 0x1b, 0x6c, 0x0f, 0x69,
        0x75, 0xce, 0x45, 0x0e, 0x34, 0xf4, 0xfe, 0x6e, 0xf4, 0x5c, 0x2c, 0xd8, 0x65, 0x12, 0x18,
        0x26, 0x74,
    ]
    .into();

    let sk = PlainSessionKey::V3_4 {
        key: bad_key,
        sym_alg: SYM_ALG,
    };

    // Decryption may succeed (garbage parses as valid structure), but reading
    // to the end must fail with MDC error
    let encrypted = Message::from_bytes(&*encrypted_data).expect("ok");
    if let Ok(mut decrypted) = encrypted.decrypt_with_session_key(sk) {
        if let Ok(data) = decrypted.as_data_vec() {
            panic!(
                "MDC check bypassed! Decrypted {} bytes with wrong key",
                data.len()
            );
        }
    };
}

/// Regression: garbage parsing as `Signature -> Signature -> Literal` must still check MDC.
#[test]
pub fn mdc_test_fast_2() {
    pretty_env_logger::try_init().ok();

    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let encrypted_data = make_seipdv1_msg(&mut rng);

    let bad_key: RawSessionKey = vec![
        0xcb, 0x3e, 0x1c, 0x71, 0x7d, 0xd2, 0xd6, 0x71, 0xf6, 0x36, 0x2f, 0x77, 0xbc, 0xab, 0x93,
        0x26, 0x60, 0x45, 0x71, 0x44, 0xe0, 0xf6, 0x0a, 0xba, 0x81, 0xde, 0xc5, 0x7d, 0x74, 0x27,
        0x4a, 0xbe,
    ]
    .into();

    let sk = PlainSessionKey::V3_4 {
        key: bad_key,
        sym_alg: SYM_ALG,
    };

    // Decryption may succeed (garbage parses as valid structure), but reading
    // to the end must fail with MDC error
    let encrypted = Message::from_bytes(&*encrypted_data).expect("ok");
    if let Ok(mut decrypted) = encrypted.decrypt_with_session_key(sk) {
        if let Ok(data) = decrypted.as_data_vec() {
            panic!(
                "MDC check bypassed! Decrypted {} bytes with wrong key",
                data.len()
            );
        }
    };
}

/// Fuzz: random wrong keys must never bypass MDC verification.
#[test]
#[ignore] // ~30s in release
pub fn mdc_test() {
    pretty_env_logger::try_init().ok();

    let encrypted_data: &[u8] = &{
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        make_seipdv1_msg(&mut rng)
    };

    let total_iterations: u64 = 2_500_000;
    eprintln!("Running MDC fuzz test with {} iterations", total_iterations);

    // Each rayon worker gets its own RNG seeded by thread index
    let result: Option<(u64, usize, RawSessionKey)> = (0..total_iterations)
        .into_par_iter()
        .map_init(
            || {
                let thread_idx = rayon::current_thread_index().unwrap_or(0);
                ChaCha8Rng::seed_from_u64(1000 + thread_idx as u64)
            },
            |rng, i| {
                let raw = random_session_key(rng);
                let encrypted = Message::from_bytes(encrypted_data).expect("valid message");

                let Message::Encrypted {
                    edata: Edata::SymEncryptedProtectedData { reader },
                    ..
                } = &encrypted
                else {
                    panic!("expected SymEncryptedProtectedData")
                };
                assert!(matches!(
                    reader.config(),
                    ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1)
                ));

                let sk = PlainSessionKey::V3_4 {
                    key: raw.clone(),
                    sym_alg: SYM_ALG,
                };

                if let Ok(mut decrypted) = encrypted.decrypt_with_session_key(sk) {
                    if let Ok(data) = decrypted.as_data_vec() {
                        return Some((i, data.len(), raw));
                    }
                }
                None
            },
        )
        .find_any(|opt| opt.is_some())
        .flatten();

    if let Some((iteration, len, key)) = result {
        panic!(
            "MDC bypass at iteration {}: decrypted {} bytes with key {:02x?}",
            iteration,
            len,
            key.as_ref()
        );
    }

    eprintln!("MDC fuzz test passed: {} iterations", total_iterations);
}
