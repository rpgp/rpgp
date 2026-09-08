use criterion::{black_box, criterion_group, BenchmarkId, Criterion};
use pgp::{
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::StringToKey,
};
use rand::distr::{Alphanumeric, SampleString};

fn bench_s2k(c: &mut Criterion) {
    let sizes = [10, 100, 1000];
    let mut rng = rand::rng();

    let mut group = c.benchmark_group("s2k");
    {
        let algs = [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha512,
        ];
        let counts = [
            1u8,
            224u8,   // default in rpgp
            u8::MAX, // maximum possible
        ];
        let sym_algs = [SymmetricKeyAlgorithm::AES128, SymmetricKeyAlgorithm::AES256];

        for size in sizes {
            for sym_alg in sym_algs {
                for alg in algs {
                    for count in counts {
                        group.bench_with_input(
                            BenchmarkId::new(
                                "iterated_and_salted",
                                format!("{size}/{alg:?}/{count}/{sym_alg:?}"),
                            ),
                            &(size, alg, count, sym_alg),
                            |b,
                             &(size, alg, count, sym_alg): &(
                                usize,
                                HashAlgorithm,
                                u8,
                                SymmetricKeyAlgorithm,
                            )| {
                                let s2k = StringToKey::new_iterated(&mut rng, alg, count);
                                let passphrase = Alphanumeric.sample_string(&mut rng, size);

                                b.iter(|| {
                                    let res = s2k
                                        .derive_key(passphrase.as_bytes(), sym_alg.key_size())
                                        .unwrap();
                                    black_box(res);
                                })
                            },
                        );
                    }
                }
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_s2k);
