#![cfg(feature = "pqc-nist-bp")]
use pgp::{
    composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{KeyDetails, Password},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use testresult::TestResult;

enum TestCase {
    TransferableSecretKey {
        source: &'static str,
        primary_key_fp: &'static str,
        primary_key_alg: PublicKeyAlgorithm,
        sub_keys: Vec<(&'static str, PublicKeyAlgorithm)>,
    },
    TransferablePublicKey {
        source: &'static str,
        primary_key_alg: PublicKeyAlgorithm,
        sub_keys: Vec<PublicKeyAlgorithm>,
    },
    SignedEncryptedMessage {
        sec_key: &'static str,
        pub_key: &'static str,
        msg: &'static str,
        hash: HashAlgorithm,
    },
}

impl TestCase {
    fn test(&self) -> TestResult {
        match self {
            Self::TransferableSecretKey {
                source,
                primary_key_fp,
                primary_key_alg,
                sub_keys,
            } => {
                let (key, _) = SignedSecretKey::from_armor_file(source)?;

                assert_eq!(key.primary_key.algorithm(), *primary_key_alg);
                assert_eq!(&key.primary_key.fingerprint().to_string(), primary_key_fp);

                for ((fp, alg), sub_key) in sub_keys.iter().zip(key.secret_subkeys.iter()) {
                    assert_eq!(sub_key.algorithm(), *alg,);
                    assert_eq!(sub_key.fingerprint().to_string(), *fp,);
                }
                assert_eq!(key.secret_subkeys.len(), sub_keys.len());

                key.verify_bindings()?;

                Ok(())
            }
            Self::TransferablePublicKey {
                source,
                primary_key_alg,
                sub_keys,
            } => {
                let (key, _) = SignedPublicKey::from_armor_file(source)?;

                assert_eq!(key.primary_key.algorithm(), *primary_key_alg);

                for (alg, sub_key) in sub_keys.iter().zip(key.public_subkeys.iter()) {
                    assert_eq!(sub_key.algorithm(), *alg,);
                }
                assert_eq!(key.public_subkeys.len(), sub_keys.len());

                key.verify_bindings()?;

                Ok(())
            }
            Self::SignedEncryptedMessage {
                sec_key,
                pub_key,
                msg,
                hash,
            } => {
                let (sec_key, _) = SignedSecretKey::from_armor_file(sec_key)?;
                sec_key.verify_bindings()?;
                let (pub_key, _) = SignedPublicKey::from_armor_file(pub_key)?;
                pub_key.verify_bindings()?;

                {
                    let (msg, _) = Message::from_armor_file(msg)?;

                    dbg!(&msg);
                    let mut msg = msg.decrypt(&Password::empty(), &sec_key)?;

                    let data = msg.as_data_string()?;
                    assert_eq!(data, "Testing\n");
                    msg.verify(&pub_key)?;
                    dbg!(&msg);
                }

                // encrypt again
                let mut rng = ChaCha8Rng::seed_from_u64(0);

                let mut builder = MessageBuilder::from_bytes("", "Testing\n")
                    .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
                builder
                    .sign(&*sec_key, Password::empty(), *hash)
                    // encrypting to the PQ subkey
                    .encrypt_to_key(&mut rng, &pub_key.public_subkeys.last().unwrap())?;

                let out = builder.to_armored_string(&mut rng, Default::default())?;

                // decrypt and verify sig again
                {
                    let (msg, _) = Message::from_armor(out.as_bytes())?;

                    dbg!(&msg);
                    let mut msg = msg.decrypt(&Password::empty(), &sec_key)?;

                    let data = msg.as_data_string()?;
                    assert_eq!(data, "Testing\n");
                    msg.verify(&pub_key)?;
                    dbg!(&msg);
                }
                Ok(())
            }
        }
    }
}

#[test]
fn test_nistp384_secret() -> TestResult {
    TestCase::TransferableSecretKey {
        source: "./tests/pqc-nist-bp/seckey-primary104-sub100.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa65NistP384,
        primary_key_fp: "a3f3ea658b8324df76694581f4f6fede3e15bb0b67c7520255d2f7868208d756",
        sub_keys: vec![(
            "16addcbd549eb8c4153c9626b6aa4dac17adeac4f79c54dfcbe4aabaa28aba1b",
            PublicKeyAlgorithm::MlKem768NistP384,
        )],
    }
    .test()
}

#[test]
fn test_nistp384_public() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc-nist-bp/pubkey-primary104-sub100.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa65NistP384,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768NistP384],
    }
    .test()
}

#[test]
fn test_nistp384_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc-nist-bp/seckey-primary104-sub100.asc",
        pub_key: "./tests/pqc-nist-bp/pubkey-primary104-sub100.asc",
        msg: "./tests/pqc-nist-bp/encrypted-alg100_signed-alg104.asc",
        hash: HashAlgorithm::Sha3_256,
    }
    .test()
}

#[test]
fn test_nistp521_secret() -> TestResult {
    TestCase::TransferableSecretKey {
        source: "./tests/pqc-nist-bp/seckey-primary105-sub101.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa87NistP521,
        primary_key_fp: "e3674a3dcbfc35fcc24b1cd7f55213a3866d17b6081c3ad5933af3d78e8c8bce",
        sub_keys: vec![(
            "c22c679c40289df8111fda26f1cc8eca6c08dcbc8e20ceaac7e6b7ddd3b040bb",
            PublicKeyAlgorithm::MlKem1024NistP521,
        )],
    }
    .test()
}

#[test]
fn test_nistp521_public() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc-nist-bp/pubkey-primary105-sub101.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa87NistP521,
        sub_keys: vec![PublicKeyAlgorithm::MlKem1024NistP521],
    }
    .test()
}

#[test]
fn test_nistp521_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc-nist-bp/seckey-primary105-sub101.asc",
        pub_key: "./tests/pqc-nist-bp/pubkey-primary105-sub101.asc",
        msg: "./tests/pqc-nist-bp/encrypted-alg101_signed-alg105.asc",
        hash: HashAlgorithm::Sha3_512,
    }
    .test()
}
