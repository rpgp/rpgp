#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{composed::Message, types::Password};

// build message from armored data, delivered here in raw bytes to simulate file
fuzz_target!(|data: &[u8]| {
    // FUZZER OBSERVATION
    // a dictionary with the expected magic header and footer strings
    // like "-----BEGIN", "-----END", is helpful to get initial coverage

    // FUZZER RESULT this can panic on some inputs
    // finding RPG-7 in ROS report 2024, fixed with 0.14.1
    let message_res = Message::from_armor(data);

    match message_res {
        Err(_) => return,
        Ok((message, _)) => {
            let _ = message.is_one_pass_signed();
            let _ = message.is_literal();

            // FUZZER RESULT this can panic on some inputs
            // finding RPG-19 in ROS report 2024, fixed with 0.14.1
            if let Ok(mut dec) = message.decrypt_with_password(&Password::from("bogus_password")) {
                let _ = dec.as_data_vec();
            }

            let _ = Message::from_armor(data).unwrap().0.as_data_vec();
            let _ = Message::from_armor(data).unwrap().0.as_data_string();

            // attempts decompression for some message types
            let (msg, _) = Message::from_armor(data).unwrap();
            if let Ok(mut msg) = msg.decompress() {
                let _ = msg.as_data_vec();
            }
        }
    }
});
