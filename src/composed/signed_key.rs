//! Signed Secret and Public Key
//!
//! Signed secret keys shall be used to sign and decrypt, whereas public keys
//! can verify and encrypt.
//! Note that technically secret keys also can by definition derive a public key
//! and hence themselves perform verify and encrypt as a public key can.
//!
//! [Key generation] is handled separately.
//! For signing directly with an RFC 9580 compliant internal hashing, see [signing and verifying based on packets].
//!
//! [Key generation]: super::key
//! [signing and verifying based on packets]: crate::packet
//!
//! # Sign and Verify Example
//!
//! ```rust
//! # const DATA :&'static [u8] = b"Hello World";
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, SignatureVersionSpecific, UserId};
//! # use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
//! # use pgp::types::{self, VerifyingKey, SigningKey, CompressionAlgorithm, Password};
//! # use rand::rng;
//! # use smallvec::*;
//! #
//! # let mut rng = rng();
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
//! #     HashAlgorithm::Sha256,
//! # ])
//! # .preferred_compression_algorithms(smallvec![
//! #     CompressionAlgorithm::ZLIB,
//! # ]);
//! # let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! # let signed_secret_key = secret_key_params.generate(&mut rng).expect("Failed to generate a plain key.");
//! # let public_key = signed_secret_key.public_key();
//! let signing_key = &signed_secret_key.primary_key;
//! let verification_key = public_key;
//!
//! use pgp::{packet::{PacketTrait, PacketHeader, Signature, SignatureConfig}, types::{PacketLength, Tag, Timestamp, KeyDetails as _}};
//!
//! let now = Timestamp::now();
//!
//! let passwd = Password::empty();
//!
//! // simulate a digest, make sure it is a compliant produce with RFC 9580
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
//!     .sign(&passwd, HashAlgorithm::Sha256, digest)
//!     .expect("Failed to crate signature");
//!
//! // the signature can already be verified
//! verification_key
//!     .verify(HashAlgorithm::Sha256, digest, &signature)
//!     .expect("Failed to validate signature");
//!
//! // wraps the signature in the appropriate package fmt ready to be serialized
//! let signature = Signature::from_config(
//!     SignatureConfig {
//!         typ: packet::SignatureType::Binary,
//!         pub_alg: PublicKeyAlgorithm::RSA,
//!         hash_alg: HashAlgorithm::Sha256,
//!         hashed_subpackets: vec![
//!             packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(now)).unwrap(),
//!             packet::Subpacket::regular(packet::SubpacketData::IssuerFingerprint(signing_key.fingerprint())).unwrap(),
//!         ],
//!         unhashed_subpackets: vec![],
//!         version_specific: SignatureVersionSpecific::V4,
//!     },
//!     [digest[0], digest[1]],
//!     signature,
//! ).unwrap();
//!
//! // sign and write the package (the package written here is NOT RFC 9580 compliant)
//! let mut signature_bytes = Vec::with_capacity(1024);
//!
//! signature.to_writer_with_header(&mut signature_bytes).expect("Write must succeed");
//!
//!
//! let raw_signature = signature.signature().unwrap();
//! verification_key
//!     .verify(HashAlgorithm::Sha256, digest, &raw_signature)
//!     .expect("Verify must succeed");
//! ```

mod key_parser;
mod parse;
mod public;
mod secret;
mod shared;

pub use self::{parse::*, public::*, secret::*, shared::*};
