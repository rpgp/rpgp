//! # Packet module
//!
//! Handles everything in relationship to packets.
//!
//! [Key generation] is handled separately as well as
//! [signing and verifying with external hashing] applied.
//!
//! [Key generation]: super::composed::key
//! [signing and verifying with external hashing]: super::composed::signed_key
//!
//! ```rust
//! # const DATA :&'static [u8] = b"Hello World";
//! # use rand::rng;
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKey, SecretSubkey, SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, SignatureVersionSpecific, UserId};
//! use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
//! use pgp::types::{self, PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm, KeyDetails as _, Password};
//! use smallvec::*;
//! #
//! # let mut key_params = SecretKeyParamsBuilder::default();
//! # key_params
//! #     .key_type(KeyType::Rsa(2048))
//! #     .can_certify(false)
//! #     .can_sign(true)
//! #     .primary_user_id("Me <me@example.com>".into())
//! #     .preferred_symmetric_algorithms(smallvec![
//! #          SymmetricKeyAlgorithm::AES256,
//! #     ])
//! #     .preferred_hash_algorithms(smallvec![
//! #          HashAlgorithm::Sha256,
//! #     ])
//! #     .preferred_compression_algorithms(smallvec![
//! #          CompressionAlgorithm::ZLIB,
//! #     ]);
//! # let mut rng = rng();
//! # let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! # let secret_key = secret_key_params.generate(&mut rng).expect("Failed to generate a plain key.");
//! # let passwd_fn = Password::empty();
//! # let signed_secret_key = secret_key.sign(&mut rng, &passwd_fn).expect("Must be able to sign its own metadata");
//! # let public_key = signed_secret_key.public_key();
//! use pgp::packet::{Signature, SignatureConfig, PacketTrait};
//!
//! let signing_key = signed_secret_key;
//! let verification_key = public_key;
//!
//!
//! let passwd_fn = Password::empty();
//!
//! let now = chrono::Utc::now();
//!
//! let mut sig_cfg = SignatureConfig::v4(packet::SignatureType::Binary, PublicKeyAlgorithm::RSA, HashAlgorithm::Sha256);
//! sig_cfg.hashed_subpackets = vec![
//!     packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(now)).unwrap(),
//!     packet::Subpacket::regular(packet::SubpacketData::Issuer(signing_key.key_id())).unwrap(),
//! ];
//!
//! let signature_packet = sig_cfg
//!      .sign(&*signing_key, &passwd_fn, DATA)
//!      .expect("Should sign");
//!
//! let mut signature_bytes = Vec::with_capacity(1024);
//! signature_packet.to_writer_with_header(&mut signature_bytes).expect("Write must succeed");
//!
//! signature_packet
//!      .verify(&*verification_key, DATA)
//!      .expect("Failed to validate signature");
//! ```

mod header;
mod many;
mod packet_sum;
mod single;

mod compressed_data;
mod gnupg_aead;
mod key;
mod literal_data;
mod marker;
mod mod_detection_code;
mod one_pass_signature;
mod padding;
mod public_key_encrypted_session_key;
mod signature;
mod sym_encrypted_data;
mod sym_encrypted_protected_data;
mod sym_key_encrypted_session_key;
mod trust;
mod user_attribute;
mod user_id;

mod public_key_parser;
mod secret_key_parser;

pub use self::{
    compressed_data::*,
    gnupg_aead::{Config as GnupgAeadConfig, GnupgAeadData},
    header::{NewPacketHeader, OldPacketHeader, PacketHeader},
    key::*,
    literal_data::*,
    many::*,
    marker::*,
    mod_detection_code::*,
    one_pass_signature::*,
    packet_sum::*,
    padding::*,
    public_key_encrypted_session_key::*,
    signature::{
        subpacket::{Subpacket, SubpacketData, SubpacketLength, SubpacketType},
        *,
    },
    sym_encrypted_data::*,
    sym_encrypted_protected_data::{
        Config as SymEncryptedProtectedDataConfig, ProtectedDataConfig, StreamDecryptor,
        SymEncryptedProtectedData,
    },
    sym_key_encrypted_session_key::*,
    trust::*,
    user_attribute::*,
    user_id::*,
};
