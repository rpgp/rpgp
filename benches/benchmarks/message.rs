use std::{
    fs::{self, File},
    io::Read,
};

use criterion::{black_box, criterion_group, BenchmarkId, Criterion, Throughput};
use pgp::{
    composed::{Deserializable, KeyType, Message, MessageBuilder, SignedSecretKey},
    crypto::{ecc_curve::ECCCurve, sym::SymmetricKeyAlgorithm},
    types::{Password, StringToKey},
};
use rand::{rng, RngCore};

use super::build_key;

fn bench_message(c: &mut Criterion) {
    let mut g = c.benchmark_group("message");
    let mut rng = rng();

    g.bench_function("parse_armored_rsa", |b| {
        let message_file_path = "./tests/openpgp-interop/testcases/messages/gnupg-v1-001.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        b.iter(|| {
            let (mut msg, _) = Message::from_armor(&bytes[..]).unwrap();
            black_box(msg.as_data_vec().unwrap())
        });
    });

    g.bench_function("parse_armored_x25519", |b| {
        let message_file_path = "./tests/openpgpjs/x25519.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        b.iter(|| {
            let (mut msg, _) = Message::from_armor(&bytes[..]).unwrap();
            black_box(msg.as_data_vec().unwrap())
        });
    });

    g.bench_function("rsa_decrypt", |b| {
        let mut decrypt_key_file =
            File::open("./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap();
        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
        let message_file_path = "./tests/openpgp-interop/testcases/messages/gnupg-v1-001.asc";
        let message_file = fs::read(message_file_path).unwrap();

        b.iter(|| {
            let (message, _headers) = Message::from_armor(&message_file[..]).unwrap();

            black_box(message.decrypt(&"test".into(), &decrypt_key).unwrap());
        });
    });

    const KB: usize = 1000;
    let sizes = [KB, 10 * KB, 100 * KB, 1000 * KB];

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("encrypt_password_s2k_iter_aes128_seipdv1", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                rng.fill_bytes(&mut bytes);

                let s2k = StringToKey::new_default(&mut rng);

                b.iter(|| {
                    let mut builder = MessageBuilder::from_reader("", &bytes[..])
                        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::default());
                    builder
                        .encrypt_with_password(s2k.clone(), &"pw".into())
                        .unwrap();

                    black_box(builder.to_vec(&mut rng).unwrap());
                });
            },
        );
    }

    for size in &sizes {
        g.throughput(Throughput::BytesDecimal(*size as u64));
        g.bench_with_input(
            BenchmarkId::new("decrypt_password_s2k_iter_aes128_seipdv1", size),
            size,
            |b, &size| {
                let mut bytes = vec![0u8; size];
                let mut rng = rand::rng();
                rng.fill_bytes(&mut bytes);

                let s2k = StringToKey::new_default(&mut rng);

                let mut builder = MessageBuilder::from_reader("", &bytes[..])
                    .seipd_v1(&mut rng, SymmetricKeyAlgorithm::default());
                builder
                    .encrypt_with_password(s2k.clone(), &"pw".into())
                    .unwrap();

                let mut encrypted = vec![];
                builder.to_writer(&mut rng, &mut encrypted).unwrap();

                // encrypted message
                let message = Message::from_bytes(&*encrypted).unwrap();

                // sanity check
                let mut res = message.decrypt_with_password(&"pw".into()).unwrap();
                assert_eq!(res.as_data_vec().unwrap(), bytes);

                b.iter(|| {
                    // decryption consumes the message, we need a new one for each iteration
                    let message = Message::from_bytes(&*encrypted).unwrap();

                    let res = message.decrypt_with_password(&"pw".into()).unwrap();
                    black_box(res);
                });
            },
        );
    }

    for (kt1, kt2, sym, asym_name, sym_name) in [
        (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519),
            SymmetricKeyAlgorithm::AES128,
            "x25519",
            "aes128",
        ),
        (
            KeyType::ECDSA(ECCCurve::P256),
            KeyType::ECDH(ECCCurve::P256),
            SymmetricKeyAlgorithm::AES128,
            "nistp256",
            "aes128",
        ),
        (
            KeyType::ECDSA(ECCCurve::P384),
            KeyType::ECDH(ECCCurve::P384),
            SymmetricKeyAlgorithm::AES192,
            "nistp384",
            "aes192",
        ),
        (
            KeyType::ECDSA(ECCCurve::P521),
            KeyType::ECDH(ECCCurve::P521),
            SymmetricKeyAlgorithm::AES256,
            "nistp521",
            "aes256",
        ),
    ] {
        for size in &sizes {
            g.throughput(Throughput::BytesDecimal(*size as u64));
            g.bench_with_input(
                BenchmarkId::new(
                    format!("{}_encrypt_key_{}_seipdv1", asym_name, sym_name),
                    size,
                ),
                size,
                |b, &size| {
                    let mut bytes = vec![0u8; size];
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut bytes);

                    let key = build_key(kt1.clone(), kt2.clone());
                    let signed_key = key.sign(&mut rng, &Password::empty()).unwrap();

                    // let message = Message::new_literal_bytes("test", &bytes).unwrap();

                    b.iter(|| {
                        let mut builder = MessageBuilder::from_reader("", &bytes[..])
                            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
                        builder
                            .encrypt_to_key(&mut rng, &signed_key.secret_subkeys[0].public_key())
                            .unwrap();

                        let mut sink = vec![];
                        builder.to_writer(&mut rng, &mut sink).unwrap();
                        black_box(sink);
                    });
                },
            );
        }

        for size in &sizes {
            g.throughput(Throughput::BytesDecimal(*size as u64));
            g.bench_with_input(
                BenchmarkId::new(
                    format!("{}_decrypt_key_{}_seipdv1", asym_name, sym_name),
                    size,
                ),
                size,
                |b, &size| {
                    let mut bytes = vec![0u8; size];
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut bytes);

                    let key = build_key(kt1.clone(), kt2.clone());
                    let signed_key = key.sign(&mut rng, &Password::empty()).unwrap();

                    let mut builder =
                        MessageBuilder::from_reader("", &bytes[..]).seipd_v1(&mut rng, sym);
                    builder
                        .encrypt_to_key(&mut rng, &signed_key.secret_subkeys[0].public_key())
                        .unwrap();

                    let mut encrypted = vec![];
                    builder.to_writer(&mut rng, &mut encrypted).unwrap();

                    // encrypted message
                    let message = Message::from_bytes(&*encrypted).unwrap();

                    // sanity check
                    let mut res = message.decrypt(&Password::empty(), &signed_key).unwrap();
                    assert_eq!(res.as_data_vec().unwrap(), bytes);

                    b.iter(|| {
                        let message = Message::from_bytes(&*encrypted).unwrap();

                        let res = message.decrypt(&Password::empty(), &signed_key).unwrap();
                        black_box(res);
                    });
                },
            );
        }
    }
}

criterion_group!(benches, bench_message);
