use std::io::Read;

use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

/// decrypt 900 mbyte of random data, seipdv2-encrypted.
///
/// to produce test data:
/// $ rsop generate-key --profile rfc9580 > /tmp/fred.tsk
/// $ cat /tmp/fred.tsk | rsop extract-cert > /tmp/fred.cert
/// $ dd if=/dev/random bs=1M count=900 | rsop encrypt /tmp/fred.cert --no-armor > /tmp/900m.seipdv2
pub fn main() {
    let (skey, _headers) =
        SignedSecretKey::from_armor_single(std::fs::File::open("/tmp/fred.tsk").unwrap()).unwrap();

    let now = std::time::Instant::now();
    let msg = Message::from_file("/tmp/900m.seipdv2").expect("msg");

    let mut dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");

    // 10^9 bytes of space for 900mbyte of plaintext
    let mut plain = Vec::with_capacity(1_000_000_000);

    let res = dec.read_to_end(&mut plain);
    eprintln!("res {res:?}");

    let elapsed = now.elapsed();
    let elapsed_milli = elapsed.as_millis();
    let mb_per_s = 900f64 / elapsed_milli as f64 * 1000f64;
    println!("Elapsed: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");
}
