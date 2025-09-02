#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{composed::Message, types::Password};

// build message from binary data
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this can panic on some inputs
    // finding RPG-7 in ROS report 2024, fixed with 0.14.1
    let message_res = Message::from_bytes(data);

    match message_res {
        Err(_) => return,
        Ok(message) => {
            let _ = message.is_one_pass_signed();
            let _ = message.is_literal();

            // -- Try to decrypt with a password and read the plaintext --
            // FUZZER RESULT this can panic on some inputs
            // finding RPG-19 in ROS report 2024, fixed with 0.14.1
            if let Ok(mut dec) = message.decrypt_with_password(&Password::from("bogus_password")) {
                let _ = dec.as_data_vec();
            }

            // -- Try to just read the content of the message, as is --
            let _ = Message::from_bytes(data).unwrap().as_data_vec();

            // -- Try to decompress and read the content --
            let msg = Message::from_bytes(data).unwrap();
            if let Ok(mut msg) = msg.decompress() {
                let _ = msg.as_data_vec();
            }
        }
    }
});
