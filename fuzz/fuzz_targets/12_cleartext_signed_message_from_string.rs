#![no_main]

use libfuzzer_sys::fuzz_target;

// build CleartextSignedMessage from string
fuzz_target!(|data: &str| {
    // FUZZER NOTE this is essentially a duplicate of the CleartextSignedMessage::from_armor() test case
    // and likely not worth additional fuzzing, but was useful to confirm the panic behavior

    // FUZZER RESULT this can panic on some inputs
    // finding RPG-15 in ROS report 2024, fixed with 0.14.1
    let _ = pgp::composed::cleartext::CleartextSignedMessage::from_string(data);
});
