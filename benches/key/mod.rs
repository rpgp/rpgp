use std::fs::File;
use test::{black_box, Bencher};

use pgp::composed::{Deserializable, PrivateKey};

#[bench]
fn bench_private_key_rsa_parse(b: &mut Bencher) {
    b.iter(|| {
        let mut decrypt_key_file =
            File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap();
        black_box(PrivateKey::from_armor_single(&mut decrypt_key_file).unwrap())
    });
}
