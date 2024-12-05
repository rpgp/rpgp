#![no_main]

use std::io::Read;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // test base64 decoding
    // FUZZER OBSERVATION no interesting behavior so far

    let reader = pgp::base64_reader::Base64Reader::new(data);
    let mut der = pgp::base64_decoder::Base64Decoder::new(reader);

    let mut res = String::new();
    let _ = der.read_to_string(&mut res);
});
