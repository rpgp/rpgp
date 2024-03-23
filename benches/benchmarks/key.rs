use std::fs::File;
use std::io::Cursor;

use criterion::{black_box, criterion_group, Criterion};

use pgp::composed::{
    Deserializable, KeyType, SecretKey, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;
use smallvec::smallvec;

fn build_key(kt: KeyType, kt_sub: KeyType) -> SecretKey {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(kt)
        .can_certify(true)
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

fn bench_key(c: &mut Criterion) {
    let mut g = c.benchmark_group("secret_key");

    g.bench_function("rsa_parse", |b| {
        let p = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc";
        b.iter(|| {
            let mut decrypt_key_file = File::open(p).unwrap();
            black_box(SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap())
        });
    });

    g.bench_function("rsa_parse_raw", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_bytes().unwrap();

        b.iter(|| black_box(SignedSecretKey::from_bytes(Cursor::new(&bytes)).unwrap()))
    });

    g.bench_function("parse_armored_rsa", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
    });

    g.bench_function("x25519_parse_armored", |b| {
        let key = build_key(KeyType::EdDSA, KeyType::ECDH)
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
    });

    g.bench_function("x25519_generate", |b| {
        b.iter(|| black_box(build_key(KeyType::EdDSA, KeyType::ECDH)))
    });

    g.bench_function("x25519_self_sign", |b| {
        let key = build_key(KeyType::EdDSA, KeyType::ECDH);

        b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()))
    });

    g.bench_function("rsa_2048_self_sign", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));

        b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()))
    });

    g.finish();
}

#[cfg(feature = "profile")]
fn profiled() -> Criterion {
    Criterion::default().with_profiler(super::profiler::GProfiler)
}

#[cfg(not(feature = "profile"))]
fn profiled() -> Criterion {
    Criterion::default()
}

criterion_group!(
    name = benches;
    config = profiled();
    targets = bench_key
);
