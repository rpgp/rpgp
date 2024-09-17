//! Signed Secret and Public Key
//!
//! Signed secret keys shall be used to sign and decrypt, where as public keys
//! can verify and encrypt.
//! Note that technically secret keys also can by definition derive a public key
//! and hence themself perform verify and encrypt as a public key can.
//!
//! [Key generation] is handled separately.
//! For signing directly with an RFC4880 compliant internal hashing, see [signing and verifying based on packets].
//!
//! [Key generation]: super::key
//! [signing and verifying based on packets]: crate::packet
//!
//! # Sign and Verify Example
//!
//! ```rust
//! # const DATA :&'static [u8] = b"Hello World";
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKey, SecretSubkey, key::SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, SignatureVersionSpecific, UserId};
//! # use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
//! # use pgp::types::{self, PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm};
//! # use rand::thread_rng;
//! # use smallvec::*;
//! #
//! # let mut key_params = SecretKeyParamsBuilder::default();
//! # key_params
//! # .key_type(KeyType::Rsa(2048))
//! # .can_certify(false)
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
//! # let secret_key = secret_key_params.generate(thread_rng()).expect("Failed to generate a plain key.");
//! # let passwd_fn = || String::new();
//! # let signed_secret_key = secret_key.sign(&mut thread_rng(), passwd_fn).expect("Must be able to sign its own metadata");
//! # let public_key = signed_secret_key.public_key();
//! let signing_key = signed_secret_key;
//! let verification_key = public_key;
//!
//! use pgp::Signature;
//! use chrono;
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
//!     hasher.update(DATA);
//!     hasher.finalize()
//! };
//! let digest = digest.as_slice();
//!
//! // creates the cryptographic core of the signature without any metadata
//! let signature = signing_key
//!     .create_signature(passwd_fn, HashAlgorithm::SHA2_256, digest)
//!     .expect("Failed to crate signature");
//!
//! // the signature can already be verified
//! verification_key
//!     .verify_signature(HashAlgorithm::SHA2_256, digest, &signature)
//!     .expect("Failed to validate signature");
//!
//! // wraps the signature in the appropriate package fmt ready to be serialized
//! let signature = Signature::v4(
//!     types::Version::Old,
//!     packet::SignatureType::Binary,
//!     PublicKeyAlgorithm::RSA,
//!     HashAlgorithm::SHA2_256,
//!     [digest[0], digest[1]],
//!     signature,
//!     vec![
//!         packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(now)),
//!         packet::Subpacket::regular(packet::SubpacketData::Issuer(signing_key.key_id())),
//!     ],
//!     vec![],
//! );
//!
//! // sign and and write the package (the package written here is NOT rfc4880 compliant)
//! let mut signature_bytes = Vec::with_capacity(1024);
//!
//! packet::write_packet(&mut signature_bytes, &signature)
//!     .expect("Write must succeed");
//!
//!
//! let raw_signature = signature.signature;
//! verification_key
//!     .verify_signature(HashAlgorithm::SHA2_256, digest, &raw_signature)
//!     .expect("Verify must succeed");
//! ```

mod key_parser;

mod parse;
mod public;
mod secret;
mod shared;

pub use self::parse::*;
pub use self::public::*;
pub use self::secret::*;
pub use self::shared::*;
