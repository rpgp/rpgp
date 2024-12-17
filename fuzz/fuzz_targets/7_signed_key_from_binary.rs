#![no_main]

use libfuzzer_sys::fuzz_target;

// build signed key from different formats
fuzz_target!(|data: &[u8]| {
    // FUZZER observation, so far no issues, coverage plateau

    // from_reader_many() handles the input as either binary (if non-ASCII) or armored (if purely ASCII)
    let _ = pgp::composed::signed_key::from_reader_many(data);
});
