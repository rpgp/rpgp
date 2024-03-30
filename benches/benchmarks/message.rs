use std::fs::{self, File};
use std::io::Read;

use criterion::{black_box, criterion_group, BenchmarkId, Criterion, Throughput};

use pgp::composed::{Deserializable, Message, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{SecretKeyTrait, StringToKey};
use pgp::KeyType;
use rand::RngCore;

use super::build_key;

fn bench_message(c: &mut Criterion) {
    let mut g = c.benchmark_group("message");

    g.bench_function("parse_armored_rsa", |b| {
        let message_file_path = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        b.iter(|| black_box(Message::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("parse_armored_x25519", |b| {
        let message_file_path = "./tests/openpgpjs/x25519.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        b.iter(|| black_box(Message::from_armor_single(&bytes[..]).unwrap()));
    });

    g.bench_function("rsa_decrypt", |b| {
        let mut decrypt_key_file =
            File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap();
        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
        let message_file_path = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc";
        let message_file = fs::read(message_file_path).unwrap();

        b.iter(|| {
            let (message, _headers) = Message::from_armor_single(&message_file[..]).unwrap();

            black_box(
                message
                    .decrypt(|| "test".to_string(), &[&decrypt_key][..])
                    .unwrap(),
            );
        });
    });

    const KB: usize = 1000;
    let sizes = [KB, 10 * KB, 100 * KB, 1000 * KB];

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("encrypt_password_s2k_iter_aes128", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut bytes);

                let s2k = StringToKey::new_default(&mut rng);
                let message = Message::new_literal_bytes("test", &bytes);

                b.iter(|| {
                    let res = message
                        .encrypt_with_password(
                            &mut rng,
                            s2k.clone(),
                            SymmetricKeyAlgorithm::default(),
                            || "pw".into(),
                        )
                        .unwrap();

                    black_box(res);
                });
            },
        );
    }

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("decrypt_password_s2k_iter_aes128", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut bytes);

                let s2k = StringToKey::new_default(&mut rng);
                let message = Message::new_literal_bytes("test", &bytes)
                    .encrypt_with_password(&mut rng, s2k, SymmetricKeyAlgorithm::default(), || {
                        "pw".into()
                    })
                    .unwrap();

                // sanity check
                let res = message.decrypt_with_password(|| "pw".into()).unwrap();
                assert_eq!(res.get_content().unwrap().unwrap(), bytes);

                b.iter(|| {
                    let res = message.decrypt_with_password(|| "pw".into()).unwrap();
                    black_box(res);
                });
            },
        );
    }

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("x25519_encrypt_key_aes128", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut bytes);

                let key = build_key(KeyType::EdDSA, KeyType::ECDH);
                let signed_key = key.sign(|| "".into()).unwrap();

                let message = Message::new_literal_bytes("test", &bytes);

                b.iter(|| {
                    let res = message
                        .encrypt_to_keys(
                            &mut rng,
                            SymmetricKeyAlgorithm::AES128,
                            &[&signed_key.secret_subkeys[0].public_key()],
                        )
                        .unwrap();

                    black_box(res);
                });
            },
        );
    }

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("x25519_decrypt_key_aes128", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut bytes);

                let key = build_key(KeyType::EdDSA, KeyType::ECDH);
                let signed_key = key.sign(|| "".into()).unwrap();

                let message = Message::new_literal_bytes("test", &bytes)
                    .encrypt_to_keys(
                        &mut rng,
                        SymmetricKeyAlgorithm::AES128,
                        &[&signed_key.secret_subkeys[0].public_key()],
                    )
                    .unwrap();

                // sanity check
                let (res, _) = message.decrypt(|| "".into(), &[&signed_key]).unwrap();
                assert_eq!(res.get_content().unwrap().unwrap(), bytes);

                b.iter(|| {
                    let res = message.decrypt(|| "".into(), &[&signed_key]).unwrap();
                    black_box(res);
                });
            },
        );
    }
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
    targets = bench_message
);
