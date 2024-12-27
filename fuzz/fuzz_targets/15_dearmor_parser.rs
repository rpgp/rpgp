#![no_main]

use buffer_redux::BufReader;
use libfuzzer_sys::fuzz_target;
use pgp::armor::Dearmor;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    // based on src/armor/reader.rs tests, see parse() function
    // FUZZER OBSERVATION no interesting behavior so far

    let mut dearmor = Dearmor::new(BufReader::new(data));
    let mut bytes = Vec::new();
    let _ = dearmor.read_to_end(&mut bytes);
});
