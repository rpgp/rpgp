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
extern crate generic_array;
extern crate itertools;
extern crate md5;
extern crate num_bigint;
extern crate num_traits;
extern crate ripemd160;
extern crate sha1;
extern crate sha2;
extern crate twofish;

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

#[macro_use]
mod errors;
mod armor;
mod packet;

pub mod email;
pub use composed::key::*;
pub mod composed;
pub mod crypto;

// public so it can be used in doc test
pub mod util;
