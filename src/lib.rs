#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::nursery))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::style))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::complexity))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::perf))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::correctness))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::result_unwrap_used))]
#![cfg_attr(feature = "cargo-clippy", deny(clippy::option_unwrap_used))]

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
extern crate itertools;
extern crate md5;
extern crate num_bigint;
extern crate num_traits;
extern crate ripemd160;
extern crate sha1;
extern crate sha2;
extern crate twofish;
extern crate x25519_dalek;
#[macro_use]
extern crate lazy_static;
extern crate block_padding;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;
extern crate buf_redux;
extern crate try_from;

#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate serde_json;

// #[cfg(test)]
extern crate hex;

#[cfg(test)]
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate glob;
#[cfg(test)]
extern crate serde;

// public so it can be used in doc test
#[macro_use]
pub mod util;

#[macro_use]
mod errors;
mod armor;
mod base64_decoder;
mod base64_reader;
mod line_reader;
mod packet;
mod types;

pub mod email;
pub use composed::key::*;
pub mod composed;
pub mod crypto;
