#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::Deserializable;

// build Public Key from single armor input
fuzz_target!(|data: &[u8]| {
    let key_res = pgp::composed::SignedPublicKey::from_armor_single(data);

    match key_res {
        // parsing failed, we're not interested further
        Err(_) => return,
        // parsing succeeded, perform checks
        Ok(combo) => {
            let (key, _) = combo;
            // for successfully parsed keys, do something with the key

            // FUZZER slow function due to fuzzer coverage on montgomery bigint operations?
            // let _ = key.verify();

            let _ = key.to_armored_bytes(None.into());
            let _ = key.expires_at();

            // FUZZER RESULT this can panic on some inputs
            // finding RPG-17 in ROS report 2024, fixed with 0.14.1
            let _ = key.as_unsigned();
        }
    }
});
