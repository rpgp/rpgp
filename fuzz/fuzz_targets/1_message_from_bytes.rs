#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::Message;
use pgp::types::Password;

// build message from binary data
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this can panic on some inputs
    // finding RPG-7 in ROS report 2024, fixed with 0.14.1
    let message_res = Message::from_bytes(data);

    match message_res {
        Err(_) => return,
        Ok(message) => {
            // not so interesting because it mostly tests external compression code?
            // let _ = message.compress(CompressionAlgorithm::ZIP);
            let _ = Message::from_bytes(data).unwrap().decompress();

            // FUZZER RESULT this can panic on some inputs
            // finding RPG-19 in ROS report 2024, fixed with 0.14.1
            if let Ok(mut dec) = message.decrypt_with_password(&Password::from("bogus_password")) {
                let _ = dec.as_data_vec();
            }

            let _ = Message::from_bytes(data).unwrap().is_one_pass_signed();
            let _ = Message::from_bytes(data).unwrap().is_literal();
            let _ = Message::from_bytes(data).unwrap().as_data_vec();

            // attempts decompression for some message types
            {
                let msg = Message::from_bytes(data).unwrap();
                if let Ok(mut msg) = msg.decompress() {
                    let _ = msg.as_data_vec();
                }
            }
        }
    }
});
