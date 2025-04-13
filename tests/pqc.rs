#![cfg(feature = "draft-pqc")]
use pgp::{
    composed::{
        Deserializable, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{KeyDetails, KeyVersion, Password},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use smallvec::smallvec;
use testresult::TestResult;

#[test]
fn test_a_1_1_transferable_secret_key() -> TestResult {
    // Sample v6 Ed25519 with ML-KEM-768+X25519 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-eddsa-sample-sk.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "2357faea8775f69acb11183f81b765cc30db7daf2768827babe202a16d07d4aa"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "fe0f1b20e62a56caacc4d68f32e5a0a3c1e7a69a7d13541fa1761a3933b5b8cf"
    );

    assert_eq!(
        key.secret_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(
        key.secret_subkeys[1].fingerprint().to_string(),
        "23eee71a76bc1eab20017a2ba4af492136ec6e6296ed60128b2223273bcb4d2c"
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_1_2_transferable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-eddsa-sample-pk.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.public_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_1_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-eddsa-sample-sk.asc")?;
    sec_key.verify()?;
    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-eddsa-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/v6-eddsa-sample-message.asc")?;

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
        .sign(&*sec_key, Password::empty(), HashAlgorithm::Sha256)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[1])?;

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

#[test]
fn test_a_2_1_transferable_secret_key() -> TestResult {
    // Sample v4 Ed25519 with ML-KEM-768+X25519 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v4-eddsa-sample-sk.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "bee82527bae0f931a3195628a3687fdca62e4844"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "3e6a6bd51614ff3810ad2256ada71a07c0afbd7d"
    );

    assert_eq!(
        key.secret_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(
        key.secret_subkeys[1].fingerprint().to_string(),
        "3c5e54c7de276f3e308e7da8c5bcde48f991e7c8"
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_2_2_transferable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v4-eddsa-sample-pk.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.public_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_2_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v4-eddsa-sample-sk.asc")?;
    sec_key.verify()?;
    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v4-eddsa-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/v4-eddsa-sample-message.asc")?;

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
        .sign(&*sec_key, Password::empty(), HashAlgorithm::Sha256)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[1])?;

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

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-mldsa-65-sample-sk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::MlDsa65Ed25519
    );
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "42120bfb467bf42c8a3eecb7fd38a8ba426ae95d916f9e77c3fd3f3955e1627d"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "8333c14b27fd556d29b18141811531452dd88c23a1c09e92561521014c1cc460"
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_3_2_transferable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-65-sample-pk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::MlDsa65Ed25519
    );

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_3_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-mldsa-65-sample-sk.asc")?;
    sec_key.verify()?;
    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-65-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/v6-mldsa-65-sample-message.asc")?;

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
        .sign(&*sec_key, Password::empty(), HashAlgorithm::Sha3_256)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[0])?;

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

#[test]
fn test_a_4_1_transferable_secret_key() -> TestResult {
    // Sample ML-DSA-87+Ed448 with ML-KEM-1024+X448 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-mldsa-87-sample-sk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::MlDsa87Ed448
    );
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "4141f9deb6ee8c3f8484c3e0d0f41796da5c6b8e6994145e3a335f557cf544c3"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem1024X448
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "8cc1fdaed98c2f3b0601eab83fe96e06a44d234bbe61d9b04c1e81c4f66d2080"
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_4_2_transferable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-87-sample-pk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::MlDsa87Ed448
    );

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem1024X448
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_4_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-mldsa-87-sample-sk.asc")?;
    sec_key.verify()?;
    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-mldsa-87-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/v6-mldsa-87-sample-message.asc")?;

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
        .sign(&*sec_key, Password::empty(), HashAlgorithm::Sha3_512)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[0])?;

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

#[test]
fn test_a_5_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-128s with ML-KEM-768+X25519 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-sk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::SlhDsaShake128s
    );
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "e761d4ec762a5f9c35f72b0c8a030c184b903c35459e74b25341b245819ab3fe"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "1090ff914d4fb0a40eb3354aeec8575609f0f72e6ad881f54e94932cd78227f6"
    );
    assert_eq!(key.secret_subkeys.len(), 1);

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_5_2_transferable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-pk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::SlhDsaShake128s
    );

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(key.public_subkeys.len(), 1);

    key.verify()?;

    Ok(())
}

#[test]
#[ignore]
fn test_a_5_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) =
        SignedSecretKey::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-sk.asc")?;
    sec_key.verify()?;
    let (pub_key, _) =
        SignedPublicKey::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-pk.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/v6-slhdsa-128s-sample-message.asc")?;

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
        .sign(&*sec_key, Password::empty(), HashAlgorithm::Sha3_256)
        // encrypting to the PQ subkey
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[0])?;

    let out = builder.to_armored_string(&mut rng, Default::default())?;

    // decrypt and verify sig again
    {
        let (msg, _) = Message::from_armor(out.as_bytes())?;

        let mut msg = msg.decrypt(&Password::empty(), &sec_key)?;

        let data = msg.as_data_string()?;
        assert_eq!(data, "Testing\n");
        msg.verify(&pub_key)?;
    }
    Ok(())
}

#[test]
fn test_a_6_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-128f with ML-KEM-768+X25519 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-slhdsa-128f-sample-sk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::SlhDsaShake128f
    );
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "7625d0725493f2a0c38080e3a3928016d73ec056e4cf54b1f93a1da7794e67ad"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "cea501a4831757a33b9fa03973b81656cf2ecac6f705daf1647e1f7190366ca6"
    );

    assert_eq!(key.secret_subkeys.len(), 1);

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_7_1_transferable_secret_key() -> TestResult {
    // Sample SLH-DSA-256s with ML-KEM-1024+X448 Data

    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/v6-slhdsa-256s-sample-sk.asc")?;

    assert_eq!(
        key.primary_key.algorithm(),
        PublicKeyAlgorithm::SlhDsaShake256s
    );
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "eb55807530d02e475e5a6f403fec5ff9c60b078395fab4c9a862ec8c82a12a95"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::MlKem1024X448
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "6e8bbbed8d24472510941bf18639f7f799f86e8d8f3a8f49694e5687885388c1"
    );

    assert_eq!(key.secret_subkeys.len(), 1);

    key.verify()?;

    Ok(())
}
