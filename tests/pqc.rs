use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::KeyDetails;
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
