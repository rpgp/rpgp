use std::fs::{self, File};
use std::io::Cursor;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use pgp::composed::{
    Deserializable, KeyType, SecretKey, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;
use smallvec::smallvec;

#[cfg(feature = "profile")]
mod profiler {
    use std::path::Path;

    use criterion::profiler::Profiler;
    use gperftools::profiler::PROFILER;

    #[derive(Default)]
    pub struct GProfiler;

    impl Profiler for GProfiler {
        fn start_profiling(&mut self, benchmark_id: &str, benchmark_dir: &Path) {
            PROFILER
                .lock()
                .unwrap()
                .start(format!(
                    "{}/{}.profile",
                    benchmark_dir.display(),
                    benchmark_id
                ))
                .unwrap();
        }

        fn stop_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
            PROFILER.lock().unwrap().stop().unwrap();
        }
    }
}

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
    {
        let p = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc";
        g.throughput(Throughput::Bytes(fs::metadata(p).unwrap().len()));
        g.bench_function("rsa_parse", |b| {
            b.iter(|| {
                let mut decrypt_key_file = File::open(p).unwrap();
                black_box(SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap())
            });
        });
    }
    {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_bytes().unwrap();

        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_function("rsa_parse_raw", |b| {
            b.iter(|| black_box(SignedSecretKey::from_bytes(Cursor::new(&bytes)).unwrap()))
        });
    }

    {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048))
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None).unwrap();

        g.throughput(Throughput::Bytes(bytes.len() as u64));

        g.bench_function("parse_armored_rsa", |b| {
            b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
        });
    }

    {
        let key = build_key(KeyType::EdDSA, KeyType::ECDH)
            .sign(|| "".into())
            .unwrap();
        let bytes = key.to_armored_bytes(None).unwrap();

        g.throughput(Throughput::Bytes(bytes.len() as u64));

        g.bench_function("x25519_parse_armored", |b| {
            b.iter(|| black_box(SignedSecretKey::from_armor_single(Cursor::new(&bytes)).unwrap()));
        });
    }

    {
        g.throughput(Throughput::Elements(1));
        g.bench_function("x25519_generate", |b| {
            b.iter(|| black_box(build_key(KeyType::EdDSA, KeyType::ECDH)))
        });
    }

    {
        let key = build_key(KeyType::EdDSA, KeyType::ECDH);

        g.throughput(Throughput::Elements(1));
        g.bench_function("x25519_self_sign", |b| {
            b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()))
        });
    }

    {
        let key = build_key(KeyType::Rsa(2048), KeyType::Rsa(2048));

        g.throughput(Throughput::Elements(1));
        g.bench_function("rsa_2048_self_sign", |b| {
            b.iter(|| black_box(key.clone().sign(|| "".into()).unwrap()))
        });
    }

    g.finish();
}

#[cfg(feature = "profile")]
fn profiled() -> Criterion {
    Criterion::default().with_profiler(MyCustomProfiler)
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
criterion_main!(benches);
