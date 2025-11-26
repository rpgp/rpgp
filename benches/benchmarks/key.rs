use std::fs::File;

use criterion::{black_box, criterion_group, Criterion};
use pgp::{
    composed::{Deserializable, KeyType, SignedSecretKey},
    crypto::ecc_curve::ECCCurve,
    ser::Serialize,
};

use super::build_key;

fn bench_key(c: &mut Criterion) {
    let mut g = c.benchmark_group("secret_key");

    g.bench_function("rsa_parse", |b| {
        let p = "./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc";
        b.iter(|| {
            let mut decrypt_key_file = File::open(p).unwrap();
            black_box(SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap())
        });
    });

    g.bench_function("rsa_parse_raw", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));
        let bytes = key.to_bytes().unwrap();

        b.iter(|| black_box(SignedSecretKey::from_bytes(&bytes[..]).unwrap()))
    });

    g.bench_function("parse_armored_rsa", |b| {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));
        let bytes = key.to_armored_bytes(None.into()).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("x25519_parse_armored", |b| {
        let key = build_key(KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519));
        let bytes = key.to_armored_bytes(None.into()).unwrap();

        b.iter(|| black_box(SignedSecretKey::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("x25519_generate", |b| {
        b.iter(|| {
            black_box(build_key(
                KeyType::Ed25519Legacy,
                KeyType::ECDH(ECCCurve::Curve25519),
            ))
        })
    });

    for curve in [ECCCurve::P256, ECCCurve::P384, ECCCurve::P521] {
        g.bench_function(format!("nistp{}_parse_armored", curve.nbits()), |b| {
            let key = build_key(KeyType::ECDSA(curve.clone()), KeyType::ECDH(curve.clone()));
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
    }

    g.finish();
}

criterion_group!(benches, bench_key);
