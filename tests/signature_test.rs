use pgp::composed::{Deserializable, DetachedSignature};

#[test]
fn sig_odd() {
    let _ = pretty_env_logger::try_init();

    // signature contains an invalid issuerfingerprint packet
    let original_sig = std::fs::read_to_string("tests/sig_odd.asc").unwrap();

    let res = DetachedSignature::from_armor_single(original_sig.as_bytes());

    let Err(e) = res else {
        panic!("Signature should not be parsed.");
    };

    assert!(e.to_string().contains("Inconsistent subpacket length"));
}
