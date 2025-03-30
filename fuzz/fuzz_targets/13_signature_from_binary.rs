#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::Deserializable;

// build Signature from binary
fuzz_target!(|data: &[u8]| {
    // FUZZER RESULT this triggers ~4GB OOM with short inputs
    // finding RPG-8 in ROS report 2024, fixed with 0.14.2
    //
    // FUZZER RESULT this triggers unsigned overflows, not visible in release profile
    // finding RPG-10 in ROS report 2024, fixed with 0.14.1
    let signature_res = pgp::composed::StandaloneSignature::from_bytes(data);

    match signature_res {
        Ok(sig) => {
            // do something with the signature
            let _ = sig.signature.key_expiration_time();
            let _ = sig.signature.signature_expiration_time();
            let _ = sig.to_armored_bytes(None.into());
        }
        Err(_) => return,
    }
});
