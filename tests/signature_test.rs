#[macro_use]
extern crate pretty_assertions;

use pgp::composed::{Deserializable, StandaloneSignature};

#[test]
fn sig_odd() {
    let _ = pretty_env_logger::try_init();

    // signature contains an invalid issuerfingerprint packet
    let original_sig = std::fs::read_to_string("tests/sig_odd.asc").unwrap();

    let (sig, _headers) =
        StandaloneSignature::from_armor_single(original_sig.as_bytes()).expect("parsing");

    assert_eq!(sig.signature.config.hashed_subpackets.len(), 2);
    assert_eq!(sig.signature.config.unhashed_subpackets.len(), 3);
}
