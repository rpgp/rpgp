use std::fs::{self, File};
use test::{black_box, Bencher};

use pgp::composed::{
    Deserializable, KeyType, SecretKey, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;

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
        .preferred_symmetric_algorithms(vec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(vec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(vec![
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

#[bench]
fn bench_secret_key_rsa_2048_generate(b: &mut Bencher) {
    b.iter(|| black_box(build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))));
}

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
