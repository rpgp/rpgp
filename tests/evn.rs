#[test]
fn load_evn_pub() {
    use std::fs::File;

    let _ = pretty_env_logger::try_init();

    // "evn.cert" is a real world certificate with some unusual properties:
    // For one thing, it encodes subpacket length in the 5 byte format.
    //
    // When hashing a signature, the exact subpacket length encoding must be preserved,
    // otherwise the signature doesn't verify correctly.
    let key_file = File::open("tests/evn.cert").unwrap();

    let (mut iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");
    match iter.next().expect("result") {
        Ok(pos) => {
            eprintln!("{:#?}", pos);
            let pgp::PublicOrSecret::Public(public) = pos else {
                panic!("expect public")
            };

            public.verify().expect("verify");
        }
        Err(e) => panic!("error: {:?}", e),
    }
}
