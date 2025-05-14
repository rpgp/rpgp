use pgp::{
    composed::{
        KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
        SubkeyParamsBuilderError,
    },
    crypto::ecc_curve::ECCCurve,
    ser::Serialize,
    types::{KeyDetails, Password},
};
use rand::rng;

/// Generate a private example key and the equivalent certificate (aka public key).
/// Store these two artifacts in `example-key.priv` and `example-key.pub`, respectively.
///
/// These keys can be reused in the separate `encrypt_decrypt` example!
fn main() {
    // Generate a new OpenPGP private key (TSK)
    let secret_key = keygen(
        KeyType::Ed25519Legacy,              // primary
        KeyType::Ed25519Legacy,              // signing subkey
        KeyType::ECDH(ECCCurve::Curve25519), // encryption subkey
        KeyType::Ed25519Legacy,              // authentication subkey
        "John Doe <jdoe@example.com>",       // user id
    )
    .expect("failed during keygen");

    println!(
        "Generated key with fingerprint: {}",
        secret_key.fingerprint()
    );

    // Save the private key to a file (as binary OpenPGP data)
    let mut priv_file =
        std::fs::File::create("example-key.priv").expect("failed to create 'example-key.priv'");
    secret_key
        .to_writer(&mut priv_file)
        .expect("failed to write to 'example-key.priv'");

    // Derive the equivalent OpenPGP public key (TPK)
    // (this strips away the private elements of each component key and keeps all other elements)
    let public_key = SignedPublicKey::from(secret_key.clone());

    // Save the public key to a file (as binary OpenPGP data)
    let mut pub_file =
        std::fs::File::create("example-key.pub").expect("failed to create 'example-key.pub'");
    public_key
        .to_writer(&mut pub_file)
        .expect("failed to write to 'example-key.pub'");
}

/// Generate a v4 OpenPGP private key (consisting of a primary key, three subkeys and one User ID).
fn keygen(
    primary_key_type: KeyType,
    signing_key_type: KeyType,
    encryption_key_type: KeyType,
    auth_key_type: KeyType,
    uid: &str,
) -> Result<SignedSecretKey, SubkeyParamsBuilderError> {
    // Set up builders for subkeys
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

    // Set up parameter builder for the full private key
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

    let mut rng = rng();

    // Generate the components of the private key (in particular: the secret key packets)
    let secret_key_params = key_params.build().expect("Build secret_key_params");
    let secret_key = secret_key_params
        .generate(&mut rng)
        .expect("Generate plain key");

    // Produce binding self-signatures that link all the components together
    let signed = secret_key
        .sign(&mut rng, &Password::from(""))
        .expect("Sign SecretKey");

    Ok(signed)
}
