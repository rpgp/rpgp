#[test]
fn load_csf() {
    // Try to load a regular CSF message
    let csf_msg = std::fs::read_to_string("tests/unit-tests/csf/msg.csf").unwrap();

    let (any, _) = pgp::Any::from_armor(csf_msg.as_bytes()).expect("from_armor");
    assert!(matches![any, pgp::Any::Cleartext(_)]);
}

#[test]
fn load_empty_csf() {
    // Try to load a CSF message with entirely empty message content (i.e.: zero bytes of payload)
    let empty_csf_msg = std::fs::read_to_string("tests/unit-tests/csf/empty.csf").unwrap();

    let (any, _) = pgp::Any::from_armor(empty_csf_msg.as_bytes()).expect("from_armor");
    assert!(matches![any, pgp::Any::Cleartext(_)]);
}

#[test]
fn load_csf_starts_with_newline() {
    // Load a CSF message with the message '\ntest\n'
    let empty_csf_msg =
        std::fs::read_to_string("tests/unit-tests/csf/starts-with-newline.csf").unwrap();

    let (any, _) = pgp::Any::from_armor(empty_csf_msg.as_bytes()).expect("from_armor");

    match any {
        pgp::Any::Cleartext(csm) => {
            // Message payload with line endings normalized (CI on windows produces CRLF line endings)
            let payload = csm.text().replace("\r\n", "\n");

            assert_eq!(payload, "\ntest\n");

            // TODO: verify signature?
        }
        _ => panic!("unexpected type"),
    }
}
