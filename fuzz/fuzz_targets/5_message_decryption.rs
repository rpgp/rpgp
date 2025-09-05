#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

// build message and try decryption with a genuine private key
fuzz_target!(|data: &[u8]| {
    let message_res = Message::from_bytes(data);

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(message) => {
            // file content of ./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc
            // included here to avoid I/O operations
            let key_input = include_str!(
                "../../tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc"
            );

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            // attempt decryption
            let decryption_res = message.decrypt(&Password::empty(), &decrypt_key);

            match decryption_res {
                // the fuzzer is not clever enough to encrypt anything to the public key
                // so any "successful" decryption is likely a bug and report-worthy
                Ok(_decryption) => panic!("potential fake decryption, investigate input"),
                // not interesting
                Err(_) => {}
            }
        }
    }
});
