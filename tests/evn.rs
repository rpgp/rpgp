#[macro_use]
extern crate pretty_assertions;

use pgp::{ArmorOptions, Deserializable};

/// "evn.cert" is a real world certificate with some unusual properties:
/// For one thing, it encodes subpacket length in the 5 byte format.
///
/// When hashing a signature, the exact subpacket length encoding must be preserved,
/// otherwise the signature doesn't verify correctly.
#[test]
fn load_evn_pub() {
    let _ = pretty_env_logger::try_init();

    let original_key = std::fs::read_to_string("tests/evn.cert").unwrap();

    let (key, headers) = pgp::composed::SignedPublicKey::from_armor_single(original_key.as_bytes())
        .expect("parsing");

    key.verify().expect("failed to verify");

    let serialized_key = key
        .to_armored_string(ArmorOptions {
            headers: Some(&headers),
            ..Default::default()
        })
        .expect("failed to serialize");
    let original = original_key
        .trim()
        .replace("\r\n", "\n")
        .replace('\r', "\n");

    let serialized = serialized_key
        .trim()
        .replace("\r\n", "\n")
        .replace('\r', "\n");

    assert_eq!(original, serialized);
}
