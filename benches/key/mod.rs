use std::fs::{self, File};
use test::{black_box, Bencher};

use pgp::composed::{Deserializable, PrivateKey};

#[bench]
fn bench_private_key_rsa_parse(b: &mut Bencher) {
    let p = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc";
    b.iter(|| {
        let mut decrypt_key_file = File::open(p).unwrap();
        black_box(PrivateKey::from_armor_single(&mut decrypt_key_file).unwrap())
    });

    b.bytes = fs::metadata(p).unwrap().len();
}
