#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::Deserializable,
    types::{EncryptionKey, KeyDetails, Password, SigningKey, VerifyingKey},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// build secret key from binary
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this triggers ~4GB OOM with short inputs
    // finding RPG-8 in ROS report 2024, fixed with 0.14.2
    let key_res = pgp::composed::SignedSecretKey::from_bytes(data);

    match key_res {
        Err(_) => return,
        Ok(key) => {
            // for successfully parsed keys, do something with the key

            // key verification is slow
            // let _ = key.verify();
            let _ = key.to_armored_bytes(None.into());
            let _ = key.expiration();
            let _ = key.fingerprint();
            let _ = key.public_key();

            // FUZZER RESULT this can panic on some inputs
            // finding RPG-17 in ROS report 2024, fixed with 0.14.1
            let _ = key.details.as_unsigned();

            // just some simple data to sign, no special meaning
            let dummy_data = vec![0u8; 8];

            // indirectly calls unlock()
            // FUZZER RESULT this can panic on some inputs
            // finding RPG-20 in ROS report 2024, fixed with 0.14.1
            let signature_res = key.sign(
                &Password::empty(),
                pgp::crypto::hash::HashAlgorithm::Sha256,
                &dummy_data,
            );

            match signature_res {
                Err(_) => {}
                Ok(signature) => {
                    let _verify_res = key
                        .public_key()
                        .verify(
                            pgp::crypto::hash::HashAlgorithm::Sha256,
                            &dummy_data,
                            &signature,
                        )
                        // Verifications for "random" keys should never succeed,
                        // because the private and public key material should never match.
                        .expect_err("signature should probably not verify");
                }
            }

            // prepare for basic encryption test
            let plaintext = vec![0u8; 32];
            // fixed PRNG seed for deterministic behavior
            let mut rng = ChaCha8Rng::seed_from_u64(0);

            // FUZZER RESULT this can panic on some inputs
            // finding RPG-21 in ROS report 2024, fixed with 0.14.1
            let _ciphertext = {
                key.public_key()
                    .encrypt(&mut rng, plaintext.as_slice(), pgp::types::EskType::V6)
            };
            // behavior should be mostly identical to the above, test it anyway
            let _ciphertext = {
                key.public_key()
                    .encrypt(&mut rng, plaintext.as_slice(), pgp::types::EskType::V3_4)
            };
            return;
        }
    }
});
