use pgp::{
    composed::{
        KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
        SubkeyParamsBuilderError,
    },
    crypto::ecc_curve::ECCCurve,
    ser::Serialize,
    types::{KeyDetails, Password},
};
use rand::thread_rng;

fn main() {
    let uid = "John Doe <jdoe@example.com>";
    let secret_key = keygen(
        uid,
        KeyType::Ed25519Legacy,
        KeyType::ECDH(ECCCurve::Curve25519),
        KeyType::Ed25519Legacy,
        KeyType::Ed25519Legacy,
    )
    .unwrap();

    println!("Generated key fingerprint: {}", secret_key.fingerprint());

    let public_key: SignedPublicKey = secret_key.clone().into();

    let mut priv_file = std::fs::File::create("key.priv").unwrap();
    secret_key.to_writer(&mut priv_file).unwrap();

    let mut pub_file = std::fs::File::create("key.pub").unwrap();
    public_key.to_writer(&mut pub_file).unwrap();
}

fn keygen(
    uid: &str,
    signing_key_type: KeyType,
    encryption_key_type: KeyType,
    auth_key_type: KeyType,
    primary_key_type: KeyType,
) -> Result<SignedSecretKey, SubkeyParamsBuilderError> {
    let mut signkey = SubkeyParamsBuilder::default();
    signkey
        .key_type(signing_key_type)
        .can_sign(true)
        .can_encrypt(false)
        .can_authenticate(false);
    let mut encryptkey = SubkeyParamsBuilder::default();
    encryptkey
        .key_type(encryption_key_type)
        .can_sign(false)
        .can_encrypt(true)
        .can_authenticate(false);
    let mut authkey = SubkeyParamsBuilder::default();
    authkey
        .key_type(auth_key_type)
        .can_sign(false)
        .can_encrypt(false)
        .can_authenticate(true);
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(primary_key_type)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(false)
        .primary_user_id(uid.into())
        .subkeys(vec![
            signkey.build()?,
            encryptkey.build()?,
            authkey.build()?,
        ]);
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let secret_key = secret_key_params
        .generate(thread_rng())
        .expect("Failed to generate a plain key.");
    let signed = secret_key
        .sign(&mut thread_rng(), &Password::from(""))
        .expect("Must be able to sign its own metadata");
    Ok(signed)
}
