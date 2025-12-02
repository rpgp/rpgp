#![doc = include_str!("../README.md")]

//! # Further reading
//!
//! More usage examples are available under the respective modules:
//!
//! - [`composed`]: Operations on OpenPGP composite objects, such as
//! [Transferable Public Key]s (Certificates) or [Message]s.
//! This module covers most common OpenPGP operations, including producing and consuming messages,
//! key generation, and dealing with detached signatures.
//!
//! - [`packet`]: Lower-level packet based operations.
//!
//! - [`armor`]: Lower-level access to [ASCII Armor] functionality is exposed in the [`armor`]
//! module.
//! (However, users of rPGP will usually handle armor implicitly in the [`composed`] module)
//!
//! [Transferable Public Key]: https://www.rfc-editor.org/rfc/rfc9580#name-transferable-public-keys
//! [Message]: https://www.rfc-editor.org/rfc/rfc9580#name-openpgp-messages
//! [ASCII Armor]: https://www.rfc-editor.org/rfc/rfc9580#name-forming-ascii-armor

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![allow(clippy::missing_const_for_fn, clippy::type_complexity)]
#![deny(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

// Reexport as used in the public api
pub use bytes;

pub(crate) mod util;

pub mod adapter;
pub mod armor;
pub mod base64;
pub mod composed;
pub mod crypto;
pub mod errors;
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
