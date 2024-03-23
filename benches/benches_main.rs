use criterion::criterion_main;

mod benchmarks;

criterion_main!(
    benchmarks::key::benches,
    benchmarks::message::benches,
);
