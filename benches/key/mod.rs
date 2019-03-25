use std::fs::{self, File};
use std::io::Cursor;
use test::{black_box, Bencher};

use pgp::composed::{
    Deserializable, KeyType, SecretKey, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;

#[cfg(feature = "profile")]
use gperftools::profiler::PROFILER;

#[cfg(feature = "profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "profile")]
#[inline(always)]
fn stop_profile() {
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn stop_profile() {}

#[bench]
fn bench_secret_key_rsa_parse(b: &mut Bencher) {
    let p = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc";
    b.iter(|| {
        let mut decrypt_key_file = File::open(p).unwrap();
        black_box(SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap())
    });

    b.bytes = fs::metadata(p).unwrap().len();
}

fn build_key(kt: KeyType, kt_sub: KeyType) -> SecretKey {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(kt)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id("Me <me@mail.com>".into())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .passphrase(None)
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(kt_sub)
                .passphrase(None)
                .can_encrypt(true)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    key_params
        .generate()
        .expect("failed to generate secret key, encrypted")
}

// #[bench]
// fn bench_secret_key_rsa_2048_generate(b: &mut Bencher) {
//     b.iter(|| black_box(build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))));
// }

#[bench]
fn bench_secret_key_rsa_2048_self_sign(b: &mut Bencher) {
    let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));
    b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()));
}

#[bench]
fn bench_secret_key_x25519_generate(b: &mut Bencher) {
    b.iter(|| black_box(build_key(KeyType::EdDSA, KeyType::ECDH)));
}

#[bench]
fn bench_secret_key_x25519_self_sign(b: &mut Bencher) {
    let key = build_key(KeyType::EdDSA, KeyType::ECDH);
    b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()));
}

#[bench]
fn bench_secret_key_parse_armored_x25519(b: &mut Bencher) {
    let key = build_key(KeyType::EdDSA, KeyType::ECDH)
        .sign(|| "".into())
        .unwrap();
    let bytes = key.to_armored_bytes(None).unwrap();

    b.bytes = bytes.len() as u64;

    start_profile("parse_key_secret_armored_x25519");
    b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
    stop_profile();
}

#[bench]
fn bench_secret_key_parse_armored_rsa(b: &mut Bencher) {
    let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
        .sign(|| "".into())
        .unwrap();
    let bytes = key.to_armored_bytes(None).unwrap();
    b.bytes = bytes.len() as u64;

    start_profile("parse_key_secret_armored_rsa");
    b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
    stop_profile();
}

#[bench]
fn bench_secret_key_parse_raw_rsa(b: &mut Bencher) {
    let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
        .sign(|| "".into())
        .unwrap();
    let bytes = key.to_bytes().unwrap();
    b.bytes = bytes.len() as u64;

    start_profile("parse_key_secret_raw_rsa");
    b.iter(|| black_box(SignedSecretKey::from_bytes(Cursor::new(&bytes)).unwrap()));
    stop_profile();
}
