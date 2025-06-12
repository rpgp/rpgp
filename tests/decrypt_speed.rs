use std::io::Read;

use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

// temporary test, requires local copy of a large encrypted message
#[test]
fn speed_seipdv1() {
    // decrypt 900 mbyte of random data, seipdv1-encrypted to bob.
    // to produce a test message:

    // $ dd if=/dev/random bs=1M count=900 | rsop encrypt ~/src/rpgp/tests/draft-bre-openpgp-samples-00/bob.pub.asc --no-armor > /tmp/900m.seipdv1

    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/draft-bre-openpgp-samples-00/bob.sec.asc").unwrap(),
    )
    .unwrap();

    let msg = Message::from_file("/tmp/900m.seipdv1").expect("msg");

    let now = std::time::Instant::now();

    let mut dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");

    // 10^9 bytes of space for 900mbyte of plaintext
    let mut plain = Vec::with_capacity(1_000_000_000);

    let res = dec.read_to_end(&mut plain);
    eprintln!("res {:?}", res);

    let elapsed = now.elapsed();
    let elapsed_milli = elapsed.as_millis();
    let mb_per_s = 900f64 / elapsed_milli as f64 * 1000f64;
    println!("Elapsed: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");
}

// temporary test, requires local copy of a large encrypted message
#[test]
fn speed_seipdv2() {
    // decrypt 900 mbyte of random data, seipdv2-encrypted to fred.

    // $ rsop generate-key --profile rfc9580 > /tmp/fred.tsk
    // $ cat /tmp/fred.tsk | rsop extract-cert > /tmp/fred.cert
    // $ dd if=/dev/random bs=1M count=900 | rsop encrypt /tmp/fred.cert --no-armor > /tmp/900m.seipdv2

    let (skey, _headers) =
        SignedSecretKey::from_armor_single(std::fs::File::open("/tmp/fred.tsk").unwrap()).unwrap();

    let msg = Message::from_file("/tmp/900m.seipdv2").expect("msg");

    let now = std::time::Instant::now();

    let mut dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");

    // 10^9 bytes of space for 900mbyte of plaintext
    let mut plain = Vec::with_capacity(1_000_000_000);

    let res = dec.read_to_end(&mut plain);
    eprintln!("res {:?}", res);

    let elapsed = now.elapsed();
    let elapsed_milli = elapsed.as_millis();
    let mb_per_s = 900f64 / elapsed_milli as f64 * 1000f64;
    println!("Elapsed: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");
}
