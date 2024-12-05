#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable, Message};

// build message from string
fuzz_target!(|data: &str| {
    // internally, this uses the from_armor() parser path
    let _ = Message::from_string(data);
});
