# PGP C Interface

Installation `make install`.


- Building for `ios`:
  - Install `cargo-lipo` and `rustup target add aarch64-apple-ios x86_64-apple-ios`
  - Run `cargo lipo --release --features nightly`
  - Resulting lib is then in `../target/universal/release/libpgp_ffi.a`
