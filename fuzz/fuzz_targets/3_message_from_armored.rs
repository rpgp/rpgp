#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::Message;
use pgp::types::Password;

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
            let _ = message.decrypt_with_password(&Password::from("bogus_password"));

            let _ = Message::from_armor(data).unwrap().0.is_one_pass_signed();
            let _ = Message::from_armor(data).unwrap().0.is_literal();
            let _ = Message::from_armor(data).unwrap().0.as_data_string();
            // attempts decompression for some message types
            let _ = Message::from_armor(data).unwrap().0.get_content();
        }
    }
});
