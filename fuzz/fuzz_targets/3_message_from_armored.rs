#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable, Message};

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
        Ok(message_tuple) => {
            let (message, _) = message_tuple;
            // FUZZER RESULT this can panic on some inputs
            // finding RPG-19 in ROS report 2024, fixed with 0.14.1
            let _ = message.decrypt_with_password(|| "bogus_password".into());

            let _ = message.clone().is_one_pass_signed();
            let _ = message.clone().is_literal();
            let _ = message.clone().get_literal();
            // attempts decompression for some message types
            let _ = message.clone().get_content();
        }
    }
});
