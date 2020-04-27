//! Internal key definitions
//!
//! These APIs do not provide guaranteed RFC4880 compliance,
//! since hashing is to be done externally.
//!
//!
//! # A full sign-verify-round-trip example
//!
//! ```rust
//! use pgp::composed::{KeyType, KeyDetails, SecretKey, SecretSubkey, key::SecretKeyParamsBuilder};
//! use pgp::errors::Result;
//! use pgp::packet::{KeyFlags, UserAttribute, UserId};
//! use pgp::types::{PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm};
//! use pgp::crypto::{sym::SymmetricKeyAlgorithm, hash::HashAlgorithm};
//! use smallvec::*;
//!
//! let mut key_params = SecretKeyParamsBuilder::default();
//! key_params
//! .key_type(KeyType::Rsa(2048))
//! .can_create_certificates(false)
//! .can_sign(true)
//! .primary_user_id("Me <me@example.com>".into())
//! .preferred_symmetric_algorithms(smallvec![
//!     SymmetricKeyAlgorithm::AES256,
//! ])
//! .preferred_hash_algorithms(smallvec![
//!     HashAlgorithm::SHA2_256,
//! ])
//! .preferred_compression_algorithms(smallvec![
//!     CompressionAlgorithm::ZLIB,
//! ]);
//! let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! let secret_key = secret_key_params.generate().expect("Failed to generate a plain key.");
//! let passwd_fn = || String::new();
//! let signed_secret_key = secret_key.sign(passwd_fn).expect("Must be able to sign its own metadata");
//! let public_key = signed_secret_key.public_key();
//! ```
//!
//! using the keys, one can then move on and sign and verify a digest directly
//!
//! ```rust
//! # const DATA :&'static [u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKey, SecretSubkey, key::SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, UserId};
//! # use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm};
//! # use pgp::types::{self, PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm};
//! # use smallvec::*;
//! #
//! # let mut key_params = SecretKeyParamsBuilder::default();
//! # key_params
//! # .key_type(KeyType::Rsa(2048))
//! # .can_create_certificates(false)
//! # .can_sign(true)
//! # .primary_user_id("Me <me@example.com>".into())
//! # .preferred_symmetric_algorithms(smallvec![
//! #     SymmetricKeyAlgorithm::AES256,
//! # ])
//! # .preferred_hash_algorithms(smallvec![
//! #     HashAlgorithm::SHA2_256,
//! # ])
//! # .preferred_compression_algorithms(smallvec![
//! #     CompressionAlgorithm::ZLIB,
//! # ]);
//! # let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! # let secret_key = secret_key_params.generate().expect("Failed to generate a plain key.");
//! # let passwd_fn = || String::new();
//! # let signed_secret_key = secret_key.sign(passwd_fn).expect("Must be able to sign its own metadata");
//! # let public_key = signed_secret_key.public_key();
//! let signing_key = signed_secret_key;
//! let verification_key = public_key;
//!
//! use crate::pgp::types::KeyTrait;
//! use chrono;
//! use std::io::Cursor;
//!
//! let now = chrono::Utc::now();
//!
//! let passwd_fn = || String::new();
//!
//! // simulate a digest, make sure it is a compliant produce with RFC4880
//! // i.e. depending on the version one needs a special suffix / prefix
//! // and length encoding. The following is NOT compliant:
//! use sha2::{Sha256, Digest};
//! let digest = {
//!     let mut hasher = Sha256::new();
//!     hasher.input(DATA);
//!     hasher.result()
//! };
//! let digest = digest.as_slice();
//!
//! // creates the cryptographic core of the signature without any metadata
//! let signature = signing_key
//!     .create_signature(passwd_fn, ::pgp::crypto::HashAlgorithm::SHA2_256, digest)
//!     .expect("Failed to crate signature");
//!
//! // the signature can already be verified
//! verification_key
//!     .verify_signature(HashAlgorithm::SHA2_256, digest, &signature)
//!     .expect("Failed to validate signature");
//!
//! // wraps the signature in the apropriate package fmt ready to be serialized
//! let signature = ::pgp::Signature::new(
//!     types::Version::Old,
//!     packet::SignatureVersion::V4,
//!     packet::SignatureType::Binary,
//!     crypto::public_key::PublicKeyAlgorithm::RSA,
//!     crypto::hash::HashAlgorithm::SHA2_256,
//!     [digest[0], digest[1]],
//!     signature,
//!     vec![
//!         pgp::packet::Subpacket::SignatureCreationTime(now),
//!         pgp::packet::Subpacket::Issuer(signing_key.key_id()),
//!     ],
//!     vec![],
//! );
//!
//! // sign and and write the package (the package written here is NOT rfc4880 compliant)
//! let mut signature_bytes = Vec::with_capacity(1024);
//!
//! let mut buff = Cursor::new(&mut signature_bytes);
//! ::pgp::packet::write_packet(&mut buff, &signature).expect("Write must succeed");
//!
//!
//! let signature = signature.signature;
//! verification_key
//!     .verify_signature(pgp::crypto::HashAlgorithm::SHA2_256, digest, &signature)
//!     .expect("Verify must succeed");
//! ```

mod builder;
mod public;
mod secret;
mod shared;

pub use self::builder::*;
pub use self::public::*;
pub use self::secret::*;
pub use self::shared::*;
