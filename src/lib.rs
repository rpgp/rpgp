#![doc = include_str!("../README.md")]

//! Usage examples are available under the respective modules:
//! [Key generation], [signing and verifying with external hashing], [packet based signing and verifying].
//!
//! [Key generation]: crate::composed::key
//! [signing and verifying with external hashing]: crate::composed::signed_key
//! [packet based signing and verifying]: crate::packet

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![allow(clippy::missing_const_for_fn, clippy::type_complexity)]
#![deny(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

// Reexport as used in the public api
pub use bytes;

pub(crate) mod util;

pub mod armor;
pub mod base64;
pub mod composed;
pub mod crypto;
pub mod errors;
pub mod helper;
pub mod line_writer;
pub mod normalize_lines;
pub mod packet;
pub mod ser;
pub mod types;

mod parsing;
mod parsing_reader;

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default maximum size that gets buffered.
pub const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 1024;
