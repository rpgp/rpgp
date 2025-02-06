use std::fs::File;

#[test]
fn load_carol_sec() {
    let _ = pretty_env_logger::try_init();

    let key_file = File::open("tests/carol.sec.asc").unwrap();

    let (mut iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");
    match iter.next().expect("result") {
        Ok(pos) => eprintln!("{:?}", pos),
        Err(e) => panic!("error: {:?}", e),
    }
}

#[test]
fn load_carol_pub() {
    let _ = pretty_env_logger::try_init();

    let key_file = File::open("tests/carol.pub.asc").unwrap();

    let (mut iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");
    match iter.next().expect("result") {
        Ok(pos) => eprintln!("{:?}", pos),
        Err(e) => panic!("error: {:?}", e),
    }
}
