use std::fs::File;

use criterion::{black_box, criterion_group, Criterion};
use pgp::composed::{Deserializable, KeyType, SignedSecretKey};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;
use rand::thread_rng;

use super::build_key;

fn bench_key(c: &mut Criterion) {
    let mut rng = thread_rng();

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
            .sign(&mut rng, || "".into())
            .unwrap();
        let bytes = key.to_bytes().unwrap();

        b.iter(|| black_box(SignedSecretKey::from_bytes(&bytes[..]).unwrap()))
    });

    g.bench_function("parse_armored_rsa", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
            .sign(&mut rng, || "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None.into()).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("x25519_parse_armored", |b| {
        let key = build_key(KeyType::EdDSALegacy, KeyType::ECDH(ECCCurve::Curve25519))
            .sign(&mut rng, || "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None.into()).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("x25519_generate", |b| {
        b.iter(|| {
            black_box(build_key(
                KeyType::EdDSALegacy,
                KeyType::ECDH(ECCCurve::Curve25519),
            ))
        })
    });

    g.bench_function("x25519_self_sign", |b| {
        let key = build_key(KeyType::EdDSALegacy, KeyType::ECDH(ECCCurve::Curve25519));

        b.iter(|| black_box(key.clone().sign(&mut rng, || "".into()).unwrap()))
    });

    g.bench_function("rsa_2048_self_sign", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));

        b.iter(|| black_box(key.clone().sign(&mut rng, || "".into()).unwrap()))
    });

    for curve in [ECCCurve::P256, ECCCurve::P384, ECCCurve::P521] {
        g.bench_function(format!("nistp{}_parse_armored", curve.nbits()), |b| {
            let key = build_key(KeyType::ECDSA(curve.clone()), KeyType::ECDH(curve.clone()))
                .sign(&mut rng, || "".into())
                .unwrap();
            let bytes = key.to_armored_bytes(None.into()).unwrap();

            b.iter(|| black_box(SignedSecretKey::from_armor_single(&bytes[..]).unwrap()));
        });

        g.bench_function(format!("nistp{}_generate", curve.nbits()), |b| {
            b.iter(|| {
                black_box(build_key(
                    KeyType::ECDSA(curve.clone()),
                    KeyType::ECDH(curve.clone()),
                ))
            })
        });

        g.bench_function(format!("nistp{}_self_sign", curve.nbits()), |b| {
            let key = build_key(KeyType::ECDSA(curve.clone()), KeyType::ECDH(curve.clone()));

            b.iter(|| black_box(key.clone().sign(&mut rng, || "".into()).unwrap()))
        });
    }

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
