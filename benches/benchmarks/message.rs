use std::fs::{self, File};
use std::io::Cursor;
use std::io::Read;

use criterion::{black_box, criterion_group, Criterion, Throughput};

use pgp::composed::{Deserializable, Message, SignedSecretKey};

fn bench_message(c: &mut Criterion) {
    let mut g = c.benchmark_group("message");

    {
        let message_file_path = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_function("parse_armored_rsa", |b| {
            b.iter(|| {
                let c = Cursor::new(bytes.clone());
                black_box(Message::from_armor_single(c).unwrap())
            });
        });
    }

    {
        let message_file_path = "./tests/openpgpjs/x25519.asc";
        let mut message_file = File::open(message_file_path).unwrap();
        let mut bytes = Vec::new();
        message_file.read_to_end(&mut bytes).unwrap();

        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_function("parse_armored_x25519", |b| {
            b.iter(|| {
                let c = Cursor::new(bytes.clone());
                black_box(Message::from_armor_single(c).unwrap())
            });
        });
    }

    {
        let mut decrypt_key_file =
            File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc")
                .unwrap();
        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
        let message_file_path = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc";
        let message_file = fs::read(message_file_path).unwrap();

        g.throughput(Throughput::Bytes(message_file.len() as u64));
        g.bench_function("rsa_decrypt", |b| {
            b.iter(|| {
                let (message, _headers) =
                    Message::from_armor_single(Cursor::new(message_file.clone())).unwrap();

                black_box(
                    message
                        .decrypt(|| "test".to_string(), &[&decrypt_key][..])
                        .unwrap(),
                );
            });
        });
    }

    {
        let mut decrypt_key_file = File::open("./tests/openpgpjs/x25519.sec.asc").unwrap();
        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
        let message_file_path = "./tests/openpgpjs/x25519.asc";
        let message_file = fs::read(message_file_path).unwrap();

        g.throughput(Throughput::Bytes(message_file.len() as u64));
        g.bench_function("x25519_decrypt", |b| {
            b.iter(|| {
                let (message, _headers) =
                    Message::from_armor_single(Cursor::new(message_file.clone())).unwrap();

                black_box(
                    message
                        .decrypt(|| "moon".to_string(), &[&decrypt_key][..])
                        .unwrap(),
                );
            });
        });
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
