#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::Deserializable,
    crypto::hash::HashAlgorithm,
    types::{EncryptionKey, KeyDetails, SignatureBytes, VerifyingKey},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// build public key from binary data
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this triggers ~4GB OOM with short inputs
    // finding RPG-8 in ROS report 2024, fixed with 0.14.2
    let key_res = pgp::composed::SignedPublicKey::from_bytes(data);

    match key_res {
        Err(_) => return,
        Ok(key) => {
            // for successfully parsed keys, do something with the key

            // this is meaningful but slow
            // let _ = key.verify();

            let _ = key.to_armored_bytes(None.into());
            let _ = key.legacy_v3_expiration_days();
            let _ = key.fingerprint();

            // removed from the API in e111ba1a
            // // FUZZER RESULT this can panic on some inputs
            // // finding RPG-17 in ROS report 2024, fixed with 0.14.1
            // let _ = key.as_unsigned();

            // test the encryption
            let plaintext = vec![0u8; 128];
            let mut rng = ChaCha8Rng::seed_from_u64(0);

            let _ciphertext =
                { key.encrypt(&mut rng, plaintext.as_slice(), pgp::types::EskType::V6) };

            // test the verification
            let dummy_data = b"dummy";

            let _ = key.verify(
                HashAlgorithm::Sha256,
                dummy_data,
                &SignatureBytes::Native(plaintext.into()),
            );

            return;
        }
    }
});
