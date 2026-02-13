use pgp::{
    composed::{
        EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::CompressionAlgorithm,
};
use rand::rng;
use smallvec::smallvec;

pub mod key;
pub mod message;
pub mod s2k;

pub fn build_key(kt: KeyType, kt_sub: KeyType) -> SignedSecretKey {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(kt)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Me <me@mail.com>".into())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha1,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .passphrase(None)
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(kt_sub)
                .passphrase(None)
                .can_encrypt(EncryptionCaps::All)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    key_params
        .generate(&mut rng())
        .expect("failed to generate secret key, encrypted")
}
