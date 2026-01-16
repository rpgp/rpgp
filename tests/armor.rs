use std::io::Read;

use buffer_redux::BufReader;
use pgp::armor::Dearmor;

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
