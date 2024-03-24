use std::fs::File;
use std::io::Cursor;

use criterion::{black_box, criterion_group, Criterion};
use pgp::ser::Serialize;
use pgp::composed::{Deserializable, KeyType, SignedSecretKey};

use super::build_key;

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
