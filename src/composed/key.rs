//! Internal key definitions
//!
//! These APIs do not provide guaranteed RFC 9580 compliance,
//! since hashing is to be done externally.
//!
//!
//! # Generating a signed secret key and deriving a public key
//!
//! ```rust
//! use pgp::{
//!     composed::{KeyDetails, KeyType, SecretKeyParamsBuilder},
//!     crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
//!     errors::Result,
//!     packet::{KeyFlags, UserAttribute, UserId},
//!     types::{CompressionAlgorithm, Password},
//! };
//! use rand::rng;
//! use smallvec::*;
//!
//! let mut rng = rng();
//! let mut key_params = SecretKeyParamsBuilder::default();
//! key_params
//!     .key_type(KeyType::Rsa(2048))
//!     .can_certify(false)
//!     .can_sign(true)
//!     .primary_user_id("Me <me@example.com>".into())
//!     .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
//!     .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256])
//!     .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);
//! let secret_key_params = key_params
//!     .build()
//!     .expect("Must be able to create secret key params");
//! let signed_secret_key = secret_key_params
//!     .generate(&mut rng)
//!     .expect("Failed to generate a plain key.");
//! let public_key = signed_secret_key.public_key();
//! ```
//!
//! [Packet based signing and verifying] as well as
//! [signing and verifying with external hashing] are demoed separately.
//!
//! [Packet based signing and verifying]: super::super::packet
//! [signing and verifying with external hashing]: super::signed_key

mod builder;
mod secret;
mod shared;

pub use self::{builder::*, shared::*};
