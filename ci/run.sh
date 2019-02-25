#!/usr/bin/env bash

set -ex

export RUST_TEST_THREADS=1
export RUST_BACKTRACE=1
export RUST_TEST_NOCAPTURE=1
export OPT="--target=$TARGET --all"
export OPT_RELEASE="--release ${OPT} --all"
export OPT_RELEASE_IGNORED="--release ${OPT} -- --ignored"
export OPT_FFI_RELEASE="--manifest-path=pgp-ffi/Cargo.toml --release"

# Select cargo command: use cross by default
export CARGO_CMD=cross

# On Appveyor (windows) and Travis (x86_64-unknown-linux-gnu and apple) native targets we use cargo (no need to cross-compile):
if [[ $TARGET = *"windows"* ]] || [[ $TARGET == "x86_64-unknown-linux-gnu" ]] || [[ $TARGET = *"apple"* ]]; then
    export CARGO_CMD=cargo
fi

# Install cross if necessary:
if [[ $CARGO_CMD == "cross" ]]; then
   cargo install cross --force
fi

# Use iOS simulator for those targets that support it:
if [[ $TARGET = *"ios"* ]]; then
    # export RUSTFLAGS=-Clink-arg=-mios-simulator-version-min=7.0
    cargo build --manifest-path ios-simulator/Cargo.toml --release
    export CARGO_TARGET_X86_64_APPLE_IOS_RUNNER=$(pwd)/ios-simulator/target/release/ios-simulator
    export CARGO_TARGET_I386_APPLE_IOS_RUNNER=$(pwd)/ios-simulator/target/release/ios-simulator
fi

# Make sure TARGET is installed when using cargo:
if [[ $CARGO_CMD == "cargo" ]]; then
    rustup target add $TARGET || true
fi

# If the build should not run tests, just check that the code builds:
if [[ $NORUN == "1" ]]; then
    export CARGO_SUBCMD="build"
else
    export CARGO_SUBCMD="test"
    # If the tests should be run, always dump all test output.
    export OPT="${OPT} "
    export OPT_RELEASE="${OPT_RELEASE} "
    export OPT_RELEASE_IGNORED="${OPT_RELEASE_IGNORED} "
fi

# Run all the test configurations:
$CARGO_CMD $CARGO_SUBCMD $OPT
$CARGO_CMD $CARGO_SUBCMD $OPT_RELEASE
$CARGO_CMD $CARGO_SUBCMD $OPT_RELEASE_IGNORED

# Build the ffi lib
$CARGO_CMD build $OPT_FFI_RELEASE

# Run documentation and clippy:
if [[ $CARGO_CMD == "cargo" ]] && [[ $TARGET != *"ios"* ]]; then
    cargo doc
fi
