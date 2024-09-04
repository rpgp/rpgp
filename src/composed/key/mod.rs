//! Internal key definitions
//!
//! These APIs do not provide guaranteed RFC4880 compliance,
//! since hashing is to be done externally.
//!
//!
//! # Generating a signed secret key and deriving a public key
//!
//! ```rust
//! use pgp::composed::{
//!     key::SecretKeyParamsBuilder, KeyDetails, KeyType, SecretKey, SecretSubkey,
//! };
//! use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
//! use pgp::errors::Result;
//! use pgp::packet::{KeyFlags, UserAttribute, UserId};
//! use pgp::types::{CompressionAlgorithm, PublicKeyTrait, SecretKeyTrait};
//! use rand::thread_rng;
//! use smallvec::*;
//!
//! let mut key_params = SecretKeyParamsBuilder::default();
//! key_params
//!     .key_type(KeyType::Rsa(2048))
//!     .can_certify(false)
//!     .can_sign(true)
//!     .primary_user_id("Me <me@example.com>".into())
//!     .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
//!     .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
//!     .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);
//! let secret_key_params = key_params
//!     .build()
//!     .expect("Must be able to create secret key params");
//! let secret_key = secret_key_params
//!     .generate(thread_rng())
//!     .expect("Failed to generate a plain key.");
//! let passwd_fn = || String::new();
//! let signed_secret_key = secret_key
//!     .sign(&mut thread_rng(), passwd_fn)
//!     .expect("Must be able to sign its own metadata");
//! let public_key = signed_secret_key.public_key();
//! ```
//!
//! [Packet based signing and verifying] as well as
//! [signing and verifying with external hashing] are demoed separately.
//!
//! [Packet based signing and verifying]: super::super::packet
//! [signing and verifying with external hashing]: super::signed_key

mod builder;
mod public;
mod secret;
mod shared;

pub use self::builder::*;
pub use self::public::*;
pub use self::secret::*;
pub use self::shared::*;
