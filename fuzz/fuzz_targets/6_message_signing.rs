#![no_main]

use std::io::Read;

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::{ArmorOptions, Deserializable, Message, MessageBuilder, SignedSecretKey},
    crypto::hash::HashAlgorithm,
    types::Password,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// build message and try decryption with a genuine private key
fuzz_target!(|data: &[u8]| {
    let message_res = Message::from_bytes(data);

    let data = data.to_vec();

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(_message) => {
            // file content of ./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc
            // included here to avoid I/O operations
            let key_input = include_str!(
                "../../tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc"
            );

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            // fixed seed PRNG for determinism
            let rng = ChaCha8Rng::seed_from_u64(0);

            // FUZZER OBSERVATION contrary to initial expectations, signing does not always succeed
            let mut builder = MessageBuilder::from_bytes("", data);
            builder.sign(&*decrypt_key, Password::from("test"), HashAlgorithm::Sha256);

            let armored = builder
                .to_armored_string(rng, ArmorOptions::default())
                .unwrap();

            let signed_message_res = Message::from_armor(armored.as_bytes());
            match signed_message_res {
                Ok((mut signed_message, _)) => {
                    let mut sink = vec![];
                    let _ = signed_message.read_to_end(&mut sink);

                    let _verify_res = signed_message
                        .verify(&*decrypt_key.public_key())
                        .expect("we just signed this and expect it to verify");
                }
                // ignore
                Err(_e) => {}
            }
        }
    }
});
