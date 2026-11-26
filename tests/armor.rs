use std::io::{Cursor, Read};

use buffer_redux::BufReader;
use pgp::{
    armor::Dearmor,
    composed::{Deserializable, Message, SignedPublicKey},
};

#[test]
fn whitespace_in_armored_message_body() {
    // A GnuPG --store message, with a tab inside a base64 group and a space at the line end.
    let armored = "-----BEGIN PGP MESSAGE-----\r\n\r\n\
                   ywx\tiAF4L4QBoZWxs \r\n\
                   bwo=\r\n=srtA\r\n\
                   -----END PGP MESSAGE-----\r\n";
    let (mut msg, _) = Message::from_string(armored).unwrap();
    assert_eq!(msg.as_data_vec().unwrap(), b"hello\n");
}

#[test]
fn dearmor_fuzz_1() {
    let input = std::fs::read("tests/unit-tests/dearmor_fuzz_1").unwrap();

    let mut dearmor = Dearmor::new(BufReader::new(&input[..]));
    let mut bytes = Vec::new();

    let res = dearmor.read_to_end(&mut bytes);
    assert!(res.is_err());
}

#[test]
fn armor_polyglot() {
    // Test handling of the armored message from https://gpg.fail/polyglot
    //
    // The message contains a very long base64 line.

    let polyglot = std::fs::read_to_string("tests/unit-tests/polyglot.armor").unwrap();
    let mut dearmor = Dearmor::new(BufReader::new(polyglot.as_bytes()));

    let mut bytes = Vec::new();
    dearmor.read_to_end(&mut bytes).expect("dearmor");

    assert_eq!(bytes.len(), 15036);

    // transform into a (lossy) representation for easy substring checks
    let string = String::from_utf8_lossy(&bytes);

    // content from second block
    assert!(string.contains("hello sq"));

    // content from third block
    assert!(string.contains("PGP"));
}

#[test]
fn test_parse_armor_missing_end_marker() {
    let c = Cursor::new(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n",
    );
    // pgp 0.4.0 would hang forever if the end marker is missing.
    let res = SignedPublicKey::from_armor_single(c);

    assert!(res.is_err());
}
