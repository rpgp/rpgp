pub mod key;
pub mod message;

#[cfg(feature = "profile")]
pub mod profiler {
    use std::path::Path;

    use criterion::profiler::Profiler;
    use gperftools::profiler::PROFILER;

    #[derive(Default)]
    pub struct GProfiler;

    impl Profiler for GProfiler {
        fn start_profiling(&mut self, benchmark_id: &str, benchmark_dir: &Path) {
            let p = benchmark_dir.join(format!("{}.profile", benchmark_id));
            std::fs::create_dir_all(benchmark_dir).unwrap();
            eprintln!("writing to {}", p.display());
            PROFILER.lock().unwrap().start(p.display().to_string()).expect("failed to start profiler");
        }

        fn stop_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
            PROFILER.lock().unwrap().stop().expect("failed to stop profiler");
        }
    }
}
