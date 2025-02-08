#[macro_use]
extern crate pretty_assertions;

use pgp::{ArmorOptions, Deserializable};

#[test]
fn load_carol_sec() {
    let _ = pretty_env_logger::try_init();

    let original_key = std::fs::read_to_string("tests/carol.sec.asc").unwrap();

    let (sec_key, headers) =
        pgp::composed::SignedSecretKey::from_armor_single(original_key.as_bytes())
            .expect("parsing");

    let serialized_key = sec_key
        .to_armored_string(ArmorOptions {
            headers: Some(&headers),
            ..Default::default()
        })
        .expect("failed to serialize");

    assert_eq!(original_key.trim(), serialized_key.trim());
}

#[test]
fn load_carol_pub() {
    let _ = pretty_env_logger::try_init();

    let original_key = std::fs::read_to_string("tests/carol.pub.asc").unwrap();

    let (key, headers) = pgp::composed::SignedPublicKey::from_armor_single(original_key.as_bytes())
        .expect("parsing");

    let serialized_key = key
        .to_armored_string(ArmorOptions {
            headers: Some(&headers),
            ..Default::default()
        })
        .expect("failed to serialize");

    assert_eq!(original_key, serialized_key);
}
