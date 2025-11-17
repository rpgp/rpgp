#![cfg(feature = "draft-pqc")]
use chacha20::ChaCha8Rng;
use pgp::{
    composed::{
        Deserializable, DetachedSignature, KeyType, Message, MessageBuilder,
        SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{KeyDetails, KeyVersion, Password},
};
use rand::{CryptoRng, RngCore, SeedableRng};
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
        primary_key_fp: "c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947",
        sub_keys: vec![(
            "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d",
            PublicKeyAlgorithm::MlKem768X25519,
        )],
    }
    .test()
}

#[test]
fn test_a_1_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v6-eddsa-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768X25519],
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
        primary_key_fp: "342e5db2de345215cb2c944f7102ffed3b9cf12d",
        sub_keys: vec![(
            "e51dbfea51936988b5428fffa4f95f985ed61a51",
            PublicKeyAlgorithm::MlKem768X25519,
        )],
    }
    .test()
}

#[test]
fn test_a_2_2_transferable_public_key() -> TestResult {
    TestCase::TransferablePublicKey {
        source: "./tests/pqc/v4-eddsa-sample-pk.asc",
        primary_key_alg: PublicKeyAlgorithm::Ed25519,
        sub_keys: vec![PublicKeyAlgorithm::MlKem768X25519],
    }
    .test()
}

#[test]
fn test_a_2_3_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v4-eddsa-sample-sk.asc",
        pub_key: "./tests/pqc/v4-eddsa-sample-pk.asc",
        msg: "./tests/pqc/v4-eddsa-sample-message-v1.asc",
        hash: HashAlgorithm::Sha256,
    }
    .test()
}

#[test]
fn test_a_2_4_signed_encrypted() -> TestResult {
    TestCase::SignedEncryptedMessage {
        sec_key: "./tests/pqc/v4-eddsa-sample-sk.asc",
        pub_key: "./tests/pqc/v4-eddsa-sample-pk.asc",
        msg: "./tests/pqc/v4-eddsa-sample-message-v2.asc",
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
        primary_key_fp: "a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f",
        sub_keys: vec![(
            "7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4",
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
            DetachedSignature::from_armor_file("./tests/pqc/v6-mldsa-65-sample-signature.asc")?;

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
        primary_key_fp: "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
        sub_keys: vec![(
            "65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f",
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
            DetachedSignature::from_armor_file("./tests/pqc/v6-mldsa-87-sample-signature.asc")?;

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
        primary_key_fp: "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
        sub_keys: vec![(
            "3e8745a4bb488779e0f32480fa23f8d0bfd8c2f49d7f74e957e1c2ffc2ef4bfc",
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
        sec_key: "./tests/pqc/v6-slhdsa-128s-sample-sk.asc",
        pub_key: "./tests/pqc/v6-slhdsa-128s-sample-pk.asc",
        msg: "./tests/pqc/v6-slhdsa-128s-sample-message.asc",
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
        let (sig, _) =
            DetachedSignature::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-signature.asc")?;

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
        primary_key_fp: "d54e0307021169f7b88beb2b76e3aad0e114be1a8f982d74dba9ca51d03537f4",
        sub_keys: vec![(
            "d8875664256c382dd7f3a5ce05021088922811f5d0b1a1f8c7769944a51b7002",
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
        let (sig, _) =
            DetachedSignature::from_armor_file("./tests/pqc/v6-slhdsa-128f-sample-signature.asc")?;

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
        primary_key_fp: "72fff84863aeba67f0d1d7691173247dd427533b9d7ee76011c6f77f2ce9fa7a",
        sub_keys: vec![(
            "570a5bbab93169876a8240da35a1ada7ba8a640aabe3ab467c797214844df15f",
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
        let (sig, _) =
            DetachedSignature::from_armor_file("./tests/pqc/v6-slhdsa-256s-sample-signature.asc")?;

        dbg!(&sig);
        sig.verify(&pub_key, &b"Testing\n"[..])?;

        assert!(sig.verify(&pub_key, &b"XXX"[..]).is_err());
    }
    Ok(())
}
