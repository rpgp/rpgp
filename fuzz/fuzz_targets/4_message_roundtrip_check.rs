#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable, Message};

// test logical behavior around message handling
fuzz_target!(|data: &[u8]| {
    let m = Message::from_bytes(data);

    match m {
        // if the input was invalid, return early
        Err(_) => return,
        // if the input was a functioning message, test a round trip encoding + decoding
        // inspired by test_parse_msg() in message_test.rs
        Ok(message_ok) => {
            // serialize and check we get the same thing
            let serialized = message_ok.to_armored_bytes(None.into());

            match serialized {
                Err(_) => return,
                Ok(serialized_ok) => {
                    // and parse them again

                    // known anomalies
                    // nonfinding RPG-14 in ROS report 2024
                    // let (m2, _headers) =
                    //     Message::from_armor(&serialized_ok[..]).expect("failed round trip");

                    // assert_eq!(message_ok, m2);
                    // let _ = Message::from_armor(&serialized[..]);

                    // no known issues yet
                    let _ =
                        Message::from_armor_many(&serialized_ok[..]).expect("failed round trip");
                }
            }
        }
    }
});
