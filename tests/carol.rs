use std::fs::File;

#[test]
fn load_carol_sec() {
    let _ = pretty_env_logger::try_init();

    let key_file = File::open("tests/carol.sec.asc").unwrap();

    let (iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");

    let packets: Vec<_> = iter.collect();
    println!("found {} packets", packets.len());
    assert!(!packets.is_empty());

    for packet in packets {
        let packet = packet.unwrap();
        println!("found: {:?}", packet);
    }
}

#[test]
fn load_carol_pub() {
    let _ = pretty_env_logger::try_init();

    let key_file = File::open("tests/carol.pub.asc").unwrap();

    let (iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");
    let packets: Vec<_> = iter.collect();
    println!("found {} packets", packets.len());
    assert!(!packets.is_empty());

    for packet in packets {
        let packet = packet.unwrap();
        println!("found: {:?}", packet);
    }
}
