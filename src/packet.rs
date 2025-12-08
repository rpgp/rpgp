//! # Packet module
//!
//! Handles everything in relation to
//! [OpenPGP packets](https://www.rfc-editor.org/rfc/rfc9580#name-packet-syntax).
//!
//! Every OpenPGP object consists of a set of "packets". Usually, those are used in
//! [`composed`](crate::composed) objects, such as Transferable Public Keys, or Messages.
//!
//! Users of rPGP will usually only use this low-level packet functionality indirectly via
//! composed objects.
//!
//! However, users are able to use this low-level module, to implement operations at the packet
//! level. Be aware that the packet level API makes no attempt at being safe to use:
//! Implementing operations on raw packets requires a deep understanding of the OpenPGP format.
//!
//! # Example
//!
//! The following example program:
//!
//! - Generates a pair of bare key packets (which could be used as the primary key in a composed
//!   key object): A [`SecretKey`] and the corresponding [`PublicKey`].
//! - Configures a binary data signature using a [`SignatureConfig`].
//! - Produces a [`Signature`] packet with the secret key packet.
//! - Verifies that [`Signature`] packet against the same data, using the public key packet.
//!   This operation checks if the cryptographic signature was indeed issued by the key holder
//!   of that public key packet.
//!
//! ```
//! use pgp::{
//!     composed::KeyType,
//!     crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
//!     packet::{
//!         PubKeyInner, PublicKey, SecretKey, SignatureConfig, SignatureType, Subpacket,
//!         SubpacketData,
//!     },
//!     types::{KeyDetails, KeyVersion, Password, Timestamp},
//! };
//! use rand::rng;
//!
//! let mut rng = rng();
//!
//! let now = Timestamp::now();
//!
//! // Generate a pair of bare key packets (a "SecretKey" and a "PublicKey").
//! //
//! // (In a composed "SignedSecretKey" or "SignedPublicKey" object,
//! // such packets would serve as primary keys.)
//! let (public_params, secret_params) = KeyType::Ed25519Legacy
//!     .generate(&mut rng)
//!     .expect("generate key");
//! let pub_key_inner = PubKeyInner::new(
//!     KeyVersion::V4,
//!     KeyType::Ed25519Legacy.to_alg(),
//!     now,
//!     None,
//!     public_params,
//! )
//! .expect("create inner public key");
//! let pub_key = PublicKey::from_inner(pub_key_inner).expect("create public key");
//! let sec_key = SecretKey::new(pub_key.clone(), secret_params).expect("create secret key");
//!
//! let mut sig_cfg = SignatureConfig::v4(
//!     SignatureType::Binary,
//!     PublicKeyAlgorithm::RSA,
//!     HashAlgorithm::Sha256,
//! );
//! sig_cfg.hashed_subpackets = vec![
//!     Subpacket::regular(SubpacketData::SignatureCreationTime(now)).unwrap(),
//!     Subpacket::regular(SubpacketData::IssuerFingerprint(pub_key.fingerprint())).unwrap(),
//! ];
//!
//! const DATA: &'static [u8] = b"Hello World";
//!
//! let signature_packet = sig_cfg
//!     .sign(&sec_key, &Password::empty(), DATA)
//!     .expect("create signature packet");
//!
//! signature_packet
//!     .verify(&pub_key, DATA)
//!     .expect("Failed to validate signature");
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
    gnupg_aead::{Config as GnupgAeadDataConfig, GnupgAeadData},
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
