#!/usr/bin/env bash

set -ex

export RUST_BACKTRACE=1

if [[ $TARGET = *"ios"* ]]; then
    rustup target add $TARGET || true
    cargo install cargo-lipo --force

    RUSTFLAGS="-C codegen-units=1 -C lto=thin" cargo lipo --release --features nightly -p pgp_ffi
    cp -r target/universal/release .

    tar cvzf "librpgp-ios-universal.tar.gz" release
elif [[ $TARGET = *"windows"* ]]; then
    echo "nothing to do"
elif [[ $TARGET = *"darwin"* ]]; then
    rustup target add $TARGET || true

    cargo build --release --features nightly -p pgp_ffi --target $TARGET
    mkdir -p release/lib/pkgconfig release/include
    cp "target/${TARGET}/release/libpgp_ffi.dylib" release/lib/librpgp.dylib
    cp "target/${TARGET}/release/librpgp.h" release/include/
    cp "target/${TARGET}/release/pkgconfig/rpgp.pc" release/lib/pkgconfig

    tar cvzf "librpgp-${TARGET}.tar.gz" release
else
    # nix systems

    cargo install --git https://github.com/dignifiedquire/cross --rev fix-tty --force

    RUSTFLAGS="-C codegen-units=1" cross build --release --features nightly -p pgp_ffi --target $TARGET
    mkdir -p release/lib/pkgconfig release/include
    cp "target/${TARGET}/release/libpgp_ffi.so" release/lib/librpgp.so
    cp "target/${TARGET}/release/librpgp.h" release/include/
    cp "target/${TARGET}/release/pkgconfig/rpgp.pc" release/lib/pkgconfig

    tar cvzf "librpgp-${TARGET}.tar.gz" release
fi
