//! Handle OpenPGP objects that are composed of multiple packets, such as
//! [Transferable Public Key]s and [Message]s.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9580#name-packet-sequence-composition>
//!
//! Key generation is handled with [`SecretKeyParamsBuilder`].
//!
//! Once generated, keys are used as OpenPGP [Transferable Public Key] with [`SignedSecretKey`]
//! or [Transferable Secret Key] with [`SignedPublicKey`].
//! Those key objects can encrypt and decrypt messages, as well as issue and verify signatures.
//!
//! [Transferable Public Key]: https://www.rfc-editor.org/rfc/rfc9580#name-transferable-public-keys
//! [Transferable Secret Key]: https://www.rfc-editor.org/rfc/rfc9580#name-transferable-secret-keys
//! [Message]: https://www.rfc-editor.org/rfc/rfc9580#name-openpgp-messages
//!
//! Messages can be produced with [`MessageBuilder`], existing messages are handled with [`Message`].
//!
//! ```rust
//! # const DATA :&'static [u8] = b"Hello World";
//! # use rand::thread_rng;
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, SignatureVersionSpecific, UserId};
//! use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
//! use pgp::types::{self, SigningKey, VerifyingKey, CompressionAlgorithm, KeyDetails as _, Password};
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
//! # let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! # let signed_secret_key = secret_key_params.generate(thread_rng()).expect("Failed to generate a plain key.");
//! # let public_key = signed_secret_key.public_key();
//! use pgp::{packet::{Signature, SignatureConfig, PacketTrait}, types::Timestamp};
//!
//! let signing_key = &signed_secret_key.primary_key;
//! let verification_key = public_key;
//!
//!
//! let passwd_fn = Password::empty();
//!
//! let now = Timestamp::now();
//!
//! let mut sig_cfg = SignatureConfig::v4(packet::SignatureType::Binary, PublicKeyAlgorithm::RSA, HashAlgorithm::Sha256);
//! sig_cfg.hashed_subpackets = vec![
//!     packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(now)).unwrap(),
//!     packet::Subpacket::regular(packet::SubpacketData::IssuerFingerprint(signing_key.fingerprint())).unwrap(),
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

mod any;
mod cleartext;
mod key;
mod message;
mod shared;
mod signature;
mod signed_key;

pub use self::{
    any::Any, cleartext::CleartextSignedMessage, key::*, message::*, shared::Deserializable,
    signature::*, signed_key::*,
};
