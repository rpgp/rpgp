#!/usr/bin/env bash

set -ex

export RUST_TEST_THREADS=1
export RUST_BACKTRACE=1
export RUST_TEST_NOCAPTURE=1
export OPT="--target=$TARGET"
export OPT_RELEASE="--release ${OPT}"

# Select cargo command: use cross by default
export CARGO_CMD=cross

# On Appveyor (windows) and Travis (x86_64-unknown-linux-gnu and apple) native targets we use cargo (no need to cross-compile):
if [[ $TARGET = *"windows"* ]] || [[ $TARGET == "x86_64-unknown-linux-gnu" ]] || [[ $TARGET = *"apple"* ]]; then
    export CARGO_CMD=cargo
fi

# Install cross if necessary:
# if [[ $CARGO_CMD == "cross" ]]; then
#    cargo install cross
#fi

# Use iOS simulator for those targets that support it:
if [[ $TARGET = *"ios"* ]]; then
    export RUSTFLAGS=-Clink-arg=-mios-simulator-version-min=7.0
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
fi

# Run all the test configurations:
$CARGO_CMD $CARGO_SUBCMD $OPT
$CARGO_CMD $CARGO_SUBCMD $OPT_RELEASE

if [[ $TRAVIS_RUST_VERSION == "nightly" ]]; then
    $CARGO_CMD $CARGO_SUBCMD --features "nightly" $OPT
    $CARGO_CMD $CARGO_SUBCMD --features "nightly" $OPT_RELEASE
fi

# Run documentation and clippy:
if [[ $CARGO_CMD == "cargo" ]] && [[ $TARGET != *"ios"* ]]; then
    cargo doc
    if [[ $TRAVIS_RUST_VERSION == "nightly" ]]; then
        rustup component add clippy-preview
        cargo clippy
    fi
fi
