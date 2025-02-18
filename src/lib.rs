#![doc = include_str!("../README.md")]

//! Usage examples are available under the respective modules:
//! [Key generation], [signing and verifying with external hashing], [packet based signing and verifying].
//!
//! [Key generation]: crate::composed::key
//! [signing and verifying with external hashing]: crate::composed::signed_key
//! [packet based signing and verifying]: crate::packet

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::style,
    clippy::perf,
    clippy::complexity,
    clippy::correctness,
    clippy::unwrap_used,
    rust_2018_idioms
)]
#![allow(
    clippy::missing_const_for_fn,
    clippy::use_self,
    clippy::needless_borrows_for_generic_args,
    clippy::type_complexity,
    clippy::incompatible_msrv
)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

// public so it can be used in doc test
#[macro_use]
pub mod util;

#[macro_use]
pub mod errors;
pub mod armor;
pub mod base64_decoder;
pub mod base64_reader;
pub mod composed;
pub mod crypto;
pub mod line_writer;
pub mod normalize_lines;
pub mod packet;
pub mod ser;
pub mod types;

// reexports for easier use
#[allow(unused_imports)]
pub use self::composed::key::*;
pub use self::composed::*;
pub use self::packet::Signature;

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default maximum size that gets buffered.
pub const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 1024;
