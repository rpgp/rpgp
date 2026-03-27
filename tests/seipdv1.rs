use std::io::Read;

use pgp::{
    composed::{
        DecryptionOptions, Edata, Message, MessageBuilder, PlainSessionKey, RawSessionKey, TheRing,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig},
    types::Seipdv1ReadMode,
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use snafu::AsErrorSource;

const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

fn make_seipdv1_msg<RAND>(mut rng: RAND, len: usize) -> (Vec<u8>, RawSessionKey)
where
    RAND: CryptoRng + Rng,
{
    let input_data: Vec<u8> = b"hello world".iter().cycle().cloned().take(len).collect();

    eprintln!("input len: {}", input_data.len());

    let raw = random_session_key(&mut rng);

    eprintln!("encrypting to session key: {:02x?}", raw.as_ref());
    eprintln!();

    let mut builder =
        MessageBuilder::from_bytes("plaintext.txt", input_data).seipd_v1(&mut rng, SYM_ALG);
    builder.set_session_key(raw.clone()).expect("ok");

    let mut encrypted_data = Vec::new();
    builder
        .to_writer(&mut rng, &mut encrypted_data)
        .expect("ok");

    (encrypted_data, raw)
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
    let (encrypted_data, _) = make_seipdv1_msg(&mut rng, 11264);

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
    let (encrypted_data, _) = make_seipdv1_msg(&mut rng, 11264);

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
        make_seipdv1_msg(&mut rng, 11264).0
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

/// Decrypt SEIPDv1 EData with (random) wrong session keys.
///
/// This should not leak specific error from parsing the resulting (wrong and unauthenticated)
/// plaintext as a message.
///
/// The mal-decrypted and unauthenticated  "plaintext" is handled via `Message::from_edata` and
/// `Message::internal_from_bytes`.
#[test]
pub fn seipdv1_test_error_uniformity() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    // Produce an encrypted message, once
    let (encrypted_data, _) = make_seipdv1_msg(&mut rng, 11264);

    // Attempt decryption with a series of (wrong) session keys and observe the resulting errors
    for _ in 0..10_000 {
        let encrypted = Message::from_bytes(&*encrypted_data).expect("ok");

        let Message::Encrypted { ref edata, .. } = &encrypted else {
            panic!("expected encrypted data");
        };

        let Edata::SymEncryptedProtectedData { reader } = &edata else {
            panic!("expected SEIPD");
        };

        assert!(
            matches!(
                reader.config(),
                ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1)
            ),
            "Expected SEIPD v1"
        );

        // Try to decrypt with a random session key
        let raw = random_session_key(&mut rng);

        let sk = PlainSessionKey::V3_4 {
            key: raw.clone(),
            sym_alg: SYM_ALG,
        };

        let res = encrypted.decrypt_with_session_key(sk.clone());

        match res {
            Ok(mut msg) => {
                let mut out = Vec::new();
                let res = msg.read_to_end(&mut out);

                match res {
                    Ok(_) => {
                        eprintln!("Decrypted data: {:02x?}", out);
                        eprintln!("Session key: {:02x?}", raw);

                        panic!("NO MDC ERROR - this should never happen");
                    }
                    Err(e) => {
                        panic!("Unexpected: decryption error during read: {:02x?}", e);
                    }
                }
            }

            Err(e) => {
                // We expect an io::Error here

                let src = e.as_error_source();
                let s = src.to_string();

                assert_eq!(
                    &s, "IO error: Modification Detection Code error",
                    "Unexpected error '{s}'"
                );
            }
        }
    }
}

/// Decrypt SEIPDv1 EData in streaming mode.
///
/// The message is sized a bit over 3x 8192 buffering blocks.
///
/// Context for message size:
/// There are three layers of buffering readers at play (that are relevant for this scenario):
//
/// - the SEIPDv1 decryptor (StreamDecryptorInner)
/// - a PacketBodyReader that processes the decrypted stream that comes out of the SEIPD packet
/// - a LiteralDataReader that will yield decrypted data via `Message::read` on the decrypted
///   message.
///
/// Each of these layers wants to fill its 8192 bytes of buffer. And the outermost of the three
/// (the StreamDecryptorInner) will check the MDC if it's reached by the time the two inner
/// readers have filled their respective 8192 byte buffers.
///
/// So in streaming mode, the first unauthenticated byte of plaintext is only released after
/// ~24 kbyte have been read, and only if the MDC hasn't been reached within that amount of data.
///
///
/// NOTE: The assumptions in this test are tied to internal details of the current implementation.
/// If the implementation of streaming decryption changes (e.g. the buffer sizes), then this test
/// may fail, and need to be adjusted.
#[test]
pub fn seipdv1_modes() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    // Produce an encrypted message.
    //
    // The size is calibrated to allow reading the first part of a corrupted message in streaming
    // mode, without triggering the MDC check.
    //
    // We corrupt the end of the message, so the streaming decryption mode shouldn't run into
    // issues where the parser for the decrypted inner message encounters invalid decrypted data.
    // (The parser should consider the decrypted data part of the literal packet, and accept it).
    //
    // Streaming decryption in rpgp currently requires a literal payload of at least 24498 in order
    // to be able to read the first byte/block. (For shorter messages, the MDC is encountered and
    // checked before releasing any plaintext, even in streaming mode.)
    let (encrypted_data, raw) = make_seipdv1_msg(&mut rng, 24500);

    let sk = PlainSessionKey::V3_4 {
        key: raw.clone(),
        sym_alg: SYM_ALG,
    };

    // corrupt message (overwrite the last 8000 bytes of the encrypted message)
    let mut corrupted_encrypted = encrypted_data.clone();
    let pos = corrupted_encrypted.len() - 8000;
    rng.fill_bytes(&mut corrupted_encrypted[pos..]);

    // -- test with default check-first seipdv1 decryption --
    let encrypted = Message::from_bytes(&*corrupted_encrypted).expect("ok");

    let res = encrypted.decrypt_with_session_key(sk.clone());

    // in the default decryption mode, we expect an immediate MDC error
    assert_eq!(
        res.err().unwrap().to_string(),
        "IO error: Modification Detection Code error"
    );

    // -- test with check-first seipdv1 decryption, and insufficient size limit --
    let encrypted = Message::from_bytes(&*corrupted_encrypted).expect("ok");

    let ring = TheRing {
        decrypt_options: DecryptionOptions::new().set_seipdv1_read_mode(
            Seipdv1ReadMode::CheckFirst {
                max_message_size: 20_000,
            },
        ),
        session_keys: vec![sk.clone()],
        ..Default::default()
    };

    let res = encrypted.decrypt_the_ring(ring, false);
    assert_eq!(
        res.err().unwrap().to_string(),
        "IO error: Input stream too long for ProtectedCheckFirst mode"
    );

    // -- test with streaming seipdv1 decryption --
    let encrypted = Message::from_bytes(&*corrupted_encrypted).expect("ok");

    let ring = TheRing {
        decrypt_options: DecryptionOptions::new().set_seipdv1_read_mode(Seipdv1ReadMode::Streaming),
        session_keys: vec![sk.clone()],
        ..Default::default()
    };

    let (mut decrypted, _) = encrypted.decrypt_the_ring(ring, false).expect("decrypt");

    // in streaming mode, reading the first 8192 byte block shouldn't trigger the MDC check
    let mut out = [0; 8192];
    let res = decrypted.read(&mut out);

    assert!(matches!(res, Ok(8192)));

    // reading from the second 8192 byte block should trigger the MDC check
    // (based on the message length and buffer sizes in rpgp)
    let res = decrypted.read(&mut out);

    assert_eq!(
        res.err().unwrap().to_string(),
        "Modification Detection Code error"
    );
}
