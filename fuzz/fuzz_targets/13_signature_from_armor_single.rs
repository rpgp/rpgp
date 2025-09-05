#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable, SignedSecretKey};

// build DetachedSignature from single armor input, and try to verify it
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this triggers ~4GB OOM with short inputs
    // finding RPG-8 in ROS report 2024, fixed with 0.14.2
    let signature_res =
        pgp::composed::DetachedSignature::from_armor_single(std::io::Cursor::new(data));

    match signature_res {
        Ok(signature) => {
            let (sig, _other) = signature;
            let _ = sig.signature.key_expiration_time();
            let _ = sig.signature.signature_expiration_time();
            let _ = sig.to_armored_bytes(None.into());

            // file content of ./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc
            // included here to avoid I/O operations
            let key_input = include_str!(
                "../../tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc"
            );

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            let _ = sig.verify(&*decrypt_key.public_key(), b"dummy");
        }
        Err(_) => return,
    }
});
