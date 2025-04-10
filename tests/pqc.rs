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
fn test_a_1_1_transferrable_secret_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedSecretKey::from_armor_file("./tests/pqc/a_1_1_key.sec.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);
    assert_eq!(
        key.primary_key.fingerprint().to_string(),
        "7f81f9d0db7cf905ed375ba0057928075faff433a70b88c0a30a022ddeaf3ac9"
    );

    assert_eq!(
        key.secret_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.secret_subkeys[0].fingerprint().to_string(),
        "e3ed45a07c5af795b7cc5a156738efb42301c10df886a341ede80fca4c99baa3"
    );

    assert_eq!(
        key.secret_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519Draft
    );
    assert_eq!(
        key.secret_subkeys[1].fingerprint().to_string(),
        "fecb6e4f8a9ad135c6b45e63d9016daf7706d7e8322fd6ed1d8b028f61d57ebe"
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_1_2_transferrable_public_key() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/pqc/a_1_2_key.pub.asc")?;

    assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);

    assert_eq!(
        key.public_subkeys[0].algorithm(),
        PublicKeyAlgorithm::X25519
    );
    assert_eq!(
        key.public_subkeys[1].algorithm(),
        PublicKeyAlgorithm::MlKem768X25519Draft
    );

    key.verify()?;

    Ok(())
}

#[test]
fn test_a_1_3_signed_encrypted() -> TestResult {
    let _ = pretty_env_logger::try_init();

    let (sec_key, _) = SignedSecretKey::from_armor_file("./tests/pqc/a_1_1_key.sec.asc")?;
    sec_key.verify()?;
    let (pub_key, _) = SignedPublicKey::from_armor_file("./tests/pqc/a_1_2_key.pub.asc")?;
    pub_key.verify()?;

    {
        let (msg, _) = Message::from_armor_file("./tests/pqc/a_1_3_msg.asc")?;

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
