#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::nursery))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::style))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::complexity))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::perf))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::correctness))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]
#![cfg_attr(
    all(feature = "cargo-clippy", not(test)),
    deny(clippy::result_unwrap_used)
)]
#![cfg_attr(
    all(feature = "cargo-clippy", not(test)),
    deny(clippy::option_unwrap_used)
)]

#[macro_use]
extern crate nom;
extern crate base64;
extern crate byteorder;
extern crate crc24;
extern crate rsa;
#[macro_use]
extern crate num_derive;
extern crate chrono;
#[macro_use]
extern crate failure;
extern crate aes;
extern crate block_modes;
extern crate blowfish;
extern crate cast5;
extern crate cfb_mode;
extern crate circular;
extern crate des;
extern crate digest;
extern crate flate2;
#[macro_use]
extern crate generic_array;
extern crate ed25519_dalek;
extern crate itertools;
extern crate md5;
extern crate num_bigint;
extern crate num_traits;
extern crate ripemd160;
extern crate sha1;
extern crate sha2;
extern crate sha3;
extern crate twofish;
extern crate x25519_dalek;
#[macro_use]
extern crate lazy_static;
extern crate block_padding;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;
extern crate buf_redux;
extern crate hex;
extern crate rand;
extern crate try_from;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate bitfield;

#[cfg(test)]
extern crate regex;
#[cfg(test)]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate glob;
#[cfg(test)]
extern crate serde;
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
pub mod email;
pub mod line_reader;
pub mod packet;
pub mod types;
pub use composed::key::*;
pub mod composed;
pub mod crypto;
pub mod de;
pub mod line_writer;
pub mod normalize_lines;
pub mod ser;
