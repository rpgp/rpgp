#![no_main]

use libfuzzer_sys::fuzz_target;

// build CleartextSignedMessage from armor
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this can panic on some inputs
    // finding RPG-15 in ROS report 2024, fixed with 0.14.1
    let message_res = pgp::composed::cleartext::CleartextSignedMessage::from_armor(data);

    match message_res {
        // parsing failed, we're not interested further
        Err(_) => return,
        // parsing succeeded, perform checks
        Ok(combo) => {
            let (message, _) = combo;

            // test some functionality
            let _ = message.signed_text();

            let data2_res = message.to_armored_bytes(None.into());
            match data2_res {
                // FUZZER EXPERIMENT: see if the export ever fails
                // not observed so far
                Err(_) => panic!("inconsistent deserialize-serialize round trip behavior"),
                Ok(_data2) => return,
            }
        }
    }
});
