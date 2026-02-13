//! Handle OpenPGP objects that are composed of multiple packets, such as
//! [Transferable Public Key]s and [Message]s.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9580#name-packet-sequence-composition>
//!
//! Key generation is handled with [`SecretKeyParamsBuilder`].
//!
//! Once generated, composed keys are used as OpenPGP [Transferable Public Key] with
//! [`SignedSecretKey`] or [Transferable Secret Key] with [`SignedPublicKey`].
//! Those key objects can encrypt and decrypt [`Message`]s, as well as produce and verify signatures
//! within messages. They can also produce and verify [`DetachedSignature`]s.
//!
//! [Transferable Public Key]: https://www.rfc-editor.org/rfc/rfc9580#name-transferable-public-keys
//! [Transferable Secret Key]: https://www.rfc-editor.org/rfc/rfc9580#name-transferable-secret-keys
//! [Message]: https://www.rfc-editor.org/rfc/rfc9580#name-openpgp-messages
//!
//! Messages can be produced with [`MessageBuilder`], existing messages are handled with [`Message`].
//!
//! # Example
//!
//! The following example program:
//!
//! - Generates a pair of [`SignedSecretKey`] ([Transferable Public Key]) and
//!   [`SignedPublicKey`] ([Transferable Secret Key]).
//! - Builds a [Message] that is encrypted to the first subkey of the [Transferable Public Key].
//! - Decrypts that [Message] again, using the [Transferable Secret Key].
//!
//! ```rust
//! use pgp::{
//!     composed::{
//!         EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
//!         SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
//!     },
//!     crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
//!     errors::Result,
//!     types::Password,
//! };
//! use rand::rng;
//! use smallvec::smallvec;
//!
//! let mut rng = rng();
//!
//! // Configure the shape of an OpenPGP Transferable Secret Key that we want to generate
//! let mut key_params = SecretKeyParamsBuilder::default();
//! key_params
//!     .key_type(KeyType::Ed25519Legacy)
//!     .can_certify(false)
//!     .can_sign(true)
//!     .primary_user_id("Me <me@example.com>".into())
//!     .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES128,])
//!     .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256,])
//!     .preferred_compression_algorithms(smallvec![])
//!     .subkeys(vec![SubkeyParamsBuilder::default()
//!         .key_type(KeyType::ECDH(ECCCurve::Curve25519))
//!         .can_encrypt(EncryptionCaps::All)
//!         .build()
//!         .expect("Must be able to create subkey")]);
//! let secret_key_params = key_params
//!     .build()
//!     .expect("Must be able to create secret key params");
//!
//! // Generate the configured Transferable Secret Key
//! let signed_secret_key: SignedSecretKey = secret_key_params
//!     .generate(&mut rng)
//!     .expect("Failed to generate a plain key.");
//!
//! // Extract a Transferable Public Key
//! let signed_public_key: SignedPublicKey = signed_secret_key.to_public_key();
//!
//! // Encrypt a message to the public key
//! const DATA: &'static [u8] = b"Hello World";
//!
//! let mut builder = MessageBuilder::from_bytes("plaintext.txt", DATA)
//!     .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
//! builder
//!     .encrypt_to_key(&mut rng, &signed_public_key.public_subkeys[0])
//!     .expect("encryption to subkey works");
//!
//! // A binary representation of the encrypted OpenPGP message
//! let encrypted: Vec<u8> = builder.to_vec(&mut rng).unwrap();
//!
//! // Parse the message and decrypt it with the secret key
//! let mut message = Message::from_bytes(&encrypted[..]).expect("parse message");
//! let mut decrypted = message
//!     .decrypt(&Password::empty(), &signed_secret_key)
//!     .expect("decrypt message");
//!
//! let plaintext = decrypted.as_data_string().expect("get data");
//!
//! assert_eq!(plaintext.as_bytes(), DATA);
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
