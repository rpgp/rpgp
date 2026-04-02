#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::DecryptionOptions;
use pgp::composed::TheRing;
use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

// build message and try decryption with a genuine private key
// this harness is a variation of another harness, and extends it by allowing some
// non-default decryption functionality
fuzz_target!(|data: &[u8]| {
    let message_res = Message::from_bytes(data);

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(message) => {
            // key file content included here to avoid I/O operations
            let key_input = include_str!("../../tests/draft-bre-openpgp-samples-00/bob.sec.asc");

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            // set a dummy password
            let pw = Password::from("password");

            let ring = TheRing {
                message_password: vec![&pw],
                secret_keys: vec![&decrypt_key],
                decrypt_options: DecryptionOptions::new().enable_legacy().enable_gnupg_aead(),
                ..Default::default()
            };

            let _ = message.decrypt_the_ring(ring, true);
        }
    }
});
