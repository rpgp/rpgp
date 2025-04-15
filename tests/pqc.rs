#![cfg(feature = "draft-pqc")]
use pgp::{
    composed::{
        Deserializable, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey, StandaloneSignature, SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{KeyDetails, KeyVersion, Password},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use smallvec::smallvec;
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

                key.verify()?;

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

                key.verify()?;

                Ok(())
            }
            Self::SignedEncryptedMessage {
                sec_key,
                pub_key,
                msg,
                hash,
            } => {
                let (sec_key, _) = SignedSecretKey::from_armor_file(sec_key)?;
                sec_key.verify()?;
                let (pub_key, _) = SignedPublicKey::from_armor_file(pub_key)?;
                pub_key.verify()?;

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
fn test_a_1_1_transferable_secret_key() -> TestResult {
    // Sample v6 Ed25519 with ML-KEM-768+X25519 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-eddsa-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        primary_key_fp: "2357faea8775f69acb11183f81b765cc30db7daf2768827babe202a16d07d4aa",
        sub_keys: vec![
            (
                "fe0f1b20e62a56caacc4d68f32e5a0a3c1e7a69a7d13541fa1761a3933b5b8cf",
                PublicKeyAlgorithm::X25519,
            ),
            (
                "23eee71a76bc1eab20017a2ba4af492136ec6e6296ed60128b2223273bcb4d2c",
                PublicKeyAlgorithm::MlKem768X25519,
            ),
        ],
    }
    .test()
}

#[test]
fn test_a_1_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-eddsa-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        sub_keys: vec![
            PublicKeyAlgorithm::X25519,
            PublicKeyAlgorithm::MlKem768X25519,
        ],
    }
    .test()
}

#[test]
fn test_a_1_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v6-eddsa-sample-sk.asc",
        pub_key: "./tests/pqc/v6-eddsa-sample-pk.asc",
        msg: "./tests/pqc/v6-eddsa-sample-message.asc",
        hash: HashAlgorithm::Sha256,
    }
    .test()
}

#[test]
fn test_a_2_1_transferable_secret_key() -> TestResult {
    // Sample v4 Ed25519 with ML-KEM-768+X25519 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v4-eddsa-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        primary_key_fp: "bee82527bae0f931a3195628a3687fdca62e4844",
        sub_keys: vec![
            (
                "3e6a6bd51614ff3810ad2256ada71a07c0afbd7d",
                PublicKeyAlgorithm::X25519,
            ),
            (
                "3c5e54c7de276f3e308e7da8c5bcde48f991e7c8",
                PublicKeyAlgorithm::MlKem768X25519,
            ),
        ],
    }
    .test()
}

#[test]
fn test_a_2_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v4-eddsa-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        sub_keys: vec![
            PublicKeyAlgorithm::X25519,
            PublicKeyAlgorithm::MlKem768X25519,
        ],
    }
    .test()
}

#[test]
fn test_a_2_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v4-eddsa-sample-sk.asc",
        pub_key: "./tests/pqc/v4-eddsa-sample-pk.asc",
        msg: "./tests/pqc/v4-eddsa-sample-message.asc",
        hash: HashAlgorithm::Sha256,
    }
    .test()
}

fn gen_key<R: RngCore + CryptoRng>(mut rng: R) -> TestResult<SignedSecretKey> {
    let key_params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V6)
        .key_type(KeyType::Ed448)
        .can_sign(true)
        .primary_user_id("Me-X <me-ml-kem-x448-rfc9580@mail.com>".into())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Sha512,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V6)
                .key_type(KeyType::MlKem1024X448)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let key = key_params
        .generate(&mut rng)
        .expect("failed to generate secret key");

    let signed_key = key.sign(&mut rng, &"".into())?;
    signed_key.verify()?;

    Ok(signed_key)
}

#[test]
fn test_ml_kem_1024_x448() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let key_a = gen_key(&mut rng)?;
    let key_b = gen_key(&mut rng)?;

    // encrypt & sign
    let mut builder = MessageBuilder::from_bytes("", "Testing\n")
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder
        .sign(&*key_a, Password::empty(), HashAlgorithm::Sha3_512)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &key_b.public_key().public_subkeys[0])?;

    let out = builder.to_armored_string(&mut rng, Default::default())?;

    // decrypt and verify sig
    {
        let (msg, _) = Message::from_armor(out.as_bytes())?;

        dbg!(&msg);
        let mut msg = msg.decrypt(&Password::empty(), &key_b)?;

        let data = msg.as_data_string()?;
        assert_eq!(data, "Testing\n");
        msg.verify(&*key_a.public_key())?;
        dbg!(&msg);
    }

    Ok(())
}

#[test]
fn test_a_3_1_transferable_secret_key() -> TestResult {
    // Sample ML-DSA-65+Ed25519 with ML-KEM-768+X25519 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-mldsa-65-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa65Ed25519,
        primary_key_fp: "42120bfb467bf42c8a3eecb7fd38a8ba426ae95d916f9e77c3fd3f3955e1627d",
        sub_keys: vec![(
            "8333c14b27fd556d29b18141811531452dd88c23a1c09e92561521014c1cc460",
            PublicKeyAlgorithm::MlKem768X25519,
        )],
    }
    .test()
}

#[test]
fn test_a_3_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-mldsa-65-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa65Ed25519,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768X25519],
    }
    .test()
}

#[test]
fn test_a_3_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v6-mldsa-65-sample-sk.asc",
        pub_key: "./tests/pqc/v6-mldsa-65-sample-pk.asc",
        msg: "./tests/pqc/v6-mldsa-65-sample-message.asc",
        hash: HashAlgorithm::Sha3_256,
    }
    .test()
}

#[test]
fn test_a_3_4_detached_signature() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-65-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (sig, _) =
            StandaloneSignature::from_armor_file("./tests/pqc/v6-mldsa-65-sample-signature.asc")?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}

#[test]
fn test_a_4_1_transferable_secret_key() -> TestResult {
    // Sample ML-DSA-87+Ed448 with ML-KEM-1024+X448 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-mldsa-87-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa87Ed448,
        primary_key_fp: "4141f9deb6ee8c3f8484c3e0d0f41796da5c6b8e6994145e3a335f557cf544c3",
        sub_keys: vec![(
            "8cc1fdaed98c2f3b0601eab83fe96e06a44d234bbe61d9b04c1e81c4f66d2080",
            PublicKeyAlgorithm::MlKem1024X448,
        )],
    }
    .test()
}

#[test]
fn test_a_4_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-mldsa-87-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::MlDsa87Ed448,
        sub_keys: vec![PublicKeyAlgorithm::MlKem1024X448],
    }
    .test()
}

#[test]
fn test_a_4_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v6-mldsa-87-sample-sk.asc",
        pub_key: "./tests/pqc/v6-mldsa-87-sample-pk.asc",
        msg: "./tests/pqc/v6-mldsa-87-sample-message.asc",
        hash: HashAlgorithm::Sha3_512,
    }
    .test()
}

#[test]
fn test_a_4_4_detached_signature() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-87-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (sig, _) =
            StandaloneSignature::from_armor_file("./tests/pqc/v6-mldsa-87-sample-signature.asc")?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}

#[test]
fn test_a_5_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-128s with ML-KEM-768+X25519 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-slhdsa-128s-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake128s,
        primary_key_fp: "e761d4ec762a5f9c35f72b0c8a030c184b903c35459e74b25341b245819ab3fe",
        sub_keys: vec![(
            "1090ff914d4fb0a40eb3354aeec8575609f0f72e6ad881f54e94932cd78227f6",
            PublicKeyAlgorithm::MlKem768X25519,
        )],
    }
    .test()
}

#[test]
fn test_a_5_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-slhdsa-128s-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake128s,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768X25519],
    }
    .test()
}

#[test]
#[ignore]
fn test_a_5_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v6-slhsa-128s-sample-sk.asc",
        pub_key: "./tests/pqc/v6-slhdsa-128s-sample-pk.asc",
        msg: "./tests/pqc/v6-mldsa-87-sample-message.asc",
        hash: HashAlgorithm::Sha3_256,
    }
    .test()
}

#[test]
fn test_a_5_4_detached_signature() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (pub_key, _) =
        SignedPublicKey::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (sig, _) = StandaloneSignature::from_armor_file(
            "./tests/pqc/v6-slhdsa-128s-sample-signature.asc",
        )?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}

#[test]
fn test_a_6_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-128f with ML-KEM-768+X25519 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-slhdsa-128f-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake128f,
        primary_key_fp: "7625d0725493f2a0c38080e3a3928016d73ec056e4cf54b1f93a1da7794e67ad",
        sub_keys: vec![(
            "cea501a4831757a33b9fa03973b81656cf2ecac6f705daf1647e1f7190366ca6",
            PublicKeyAlgorithm::MlKem768X25519,
        )],
    }
    .test()
}

#[test]
fn test_a_6_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-slhdsa-128f-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake128f,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768X25519],
    }
    .test()
}

#[test]
fn test_a_6_3_detached_signature() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (pub_key, _) =
        SignedPublicKey::from_armor_file("./tests/pqc/v6-slhdsa-128f-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (sig, _) = StandaloneSignature::from_armor_file(
            "./tests/pqc/v6-slhdsa-128f-sample-signature.asc",
        )?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}

#[test]
fn test_a_7_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-256s with ML-KEM-1024+X448 Data

    TestCase::TransferableSecretKey {
        source: "./tests/pqc/v6-slhdsa-256s-sample-sk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake256s,
        primary_key_fp: "eb55807530d02e475e5a6f403fec5ff9c60b078395fab4c9a862ec8c82a12a95",
        sub_keys: vec![(
            "6e8bbbed8d24472510941bf18639f7f799f86e8d8f3a8f49694e5687885388c1",
            PublicKeyAlgorithm::MlKem1024X448,
        )],
    }
    .test()
}

#[test]
fn test_a_7_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-slhdsa-256s-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::SlhDsaShake256s,
        sub_keys: vec![PublicKeyAlgorithm::MlKem1024X448],
    }
    .test()
}

#[test]
fn test_a_7_3_detached_signature() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (pub_key, _) =
        SignedPublicKey::from_armor_file("./tests/pqc/v6-slhdsa-256s-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (sig, _) = StandaloneSignature::from_armor_file(
            "./tests/pqc/v6-slhdsa-256s-sample-signature.asc",
        )?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}
