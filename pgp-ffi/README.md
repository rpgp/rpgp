# PGP C Interface

Installation `make install`.


- Building for `ios`:
  - Install `cargo-lipo` and `rustup target add aarch64-apple-ios x86_64-apple-ios`
  - Run `export RUSTFLAGS="-C codegen-units=1 -C lto=thin"`
  - Run `cd ../ && cargo -p pgp_ffi lipo --release --features nightly`
  - Resulting lib is then in `../target/universal/release/libpgp_ffi.a`
