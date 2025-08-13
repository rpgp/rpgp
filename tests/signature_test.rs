#[macro_use]
extern crate pretty_assertions;

use pgp::composed::{Deserializable, DetachedSignature};

#[test]
fn sig_odd() {
    let _ = pretty_env_logger::try_init();

    // signature contains an invalid issuerfingerprint packet
    let original_sig = std::fs::read_to_string("tests/sig_odd.asc").unwrap();

    let (sig, _headers) =
        DetachedSignature::from_armor_single(original_sig.as_bytes()).expect("parsing");

    assert_eq!(sig.signature.config().unwrap().hashed_subpackets.len(), 2);
    assert_eq!(sig.signature.config().unwrap().unhashed_subpackets.len(), 3);
}
