# PGP C Interface

Installation `make install`.


- Building for `ios`:
  - Install `cargo-lipo` and `rustup target add aarch64-apple-ios x86_64-apple-ios`
  - Run `export RUSTFLAGS="-C debuginfo=0 -C opt-level=s -C codegen-units=1 -C panic=abort -C lto=thin"`
  - Run `cargo lipo --release --features nightly`
  - Resulting lib is then in `../target/universal/release/libpgp_ffi.a`
