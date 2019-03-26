#!/usr/bin/env bash

set -ex

export RUST_BACKTRACE=1
export RUST_TEST_NOCAPTURE=1
export OPT="-p pgp_ffi --target=$TARGET"

# Select cargo command: use cross by default
export CARGO_CMD=cross

if [[ $TARGET = *"windows"* ]] || [[ $TARGET = *"darwin"* ]]; then
    export CARGO_CMD=cargo
fi

# Install cross if necessary:
if [[ $CARGO_CMD == "cross" ]]; then
    cargo install cross --force
fi

# Make sure TARGET is installed when using cargo:
if [[ $CARGO_CMD == "cargo" ]]; then
    rustup target add $TARGET || true
fi

if [[ $TARGET = *"ios"* ]]; then
    cargo install lippo --force

    RUSTFLAGS="-C codegen-units=1 -C lto=thin" cargo lippo --release --features nightly -p pgp_ffi
    cp -r target/universal/release/ .

elif [[ $TARGET = *"windows"* ]]; then
    cargo build --release --features nightly -p pgp_ffi --target $TARGET
    mkdir -p release/$@/lib/pkgconfig release/$@/include
    cp target/release/libpgp_ffi.dll release/$@/lib/librpgp.dll
    cp librpgp.h release/$@/include/
    cp target/release/pkgconfig/rpgp.pc release/$@/lib/pkgconfig

elif [[ $TARGET = *"darwin"* ]]; then
    cargo build --release --features nightly -p pgp_ffi --target $TARGET
    mkdir -p release/$@/lib/pkgconfig release/$@/include
    cp target/release/libpgp_ffi.dylib release/$@/lib/librpgp.dylib
    cp librpgp.h release/$@/include/
    cp target/release/pkgconfig/rpgp.pc release/$@/lib/pkgconfig
else
    # nix systems
    RUSTFLAGS="-C codegen-units=1" cross build --release --features nightly -p pgp_ffi --target $TARGET
    mkdir -p release/$@/lib/pkgconfig release/$@/include
    cp target/release/libpgp_ffi.so release/$@/lib/librpgp.so
    cp librpgp.h release/$@/include/
    cp target/release/pkgconfig/rpgp.pc release/$@/lib/pkgconfig
fi

# TODO: upload everything in release
