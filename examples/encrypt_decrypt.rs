use std::fs;

use pgp::{
    composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey},
    crypto::sym::SymmetricKeyAlgorithm,
    types::PublicKeyTrait,
};
use rand::rng;

fn main() {
    let encrypted = {
        // The cleartext we'll encrypt
        let msg = b"Secret message";

        // Load the OpenPGP public key that we'll encrypt to
        let public_key = read_public_key(&fs::read("example-key.pub").expect("public key"));

        // Encrypt the cleartext to the recipient key, and produce an encrypted OpenPGP message
        encrypt(&public_key, msg)
    };

    // Load the private OpenPGP key that can decrypt the message again
    let secret_key = read_secret_key(&fs::read("example-key.priv").expect("secret key"));

    // Perform the decryption operation, obtain the plaintext message again and print it
    let decrypted = decrypt(&secret_key, &encrypted);

    println!("Decrypted message:");
    println!("'{}'", String::from_utf8(decrypted).expect("UTF-8"));
}

/// Encrypt the cleartext data in `msg` to the second subkey of `cert`.
///
/// Note: We assume that the second subkey is the encryption subkey, because that's the form that
/// the `generate_key` example produces.
///
/// The return value is an encrypted OpenPGP message, in binary (non-armored) representation.
fn encrypt(cert: &SignedPublicKey, msg: &[u8]) -> Vec<u8> {
    // We assume the second subkey is the encryption subkey
    //
    // Note: In real-world OpenPGP applications, when dealing with unknown certificate shapes,
    // subkeys must be checked for validity for a specific type of use.
    //
    // Such logic is out of scope for this example. We assume to find the encryption key in a fixed
    // subkey slot, and assume that this subkey is valid for use.
    let encryption_subkey = &cert.public_subkeys[1];

    assert!(
        encryption_subkey.is_encryption_key(),
        "Unexpected subkey layout"
    );

    let mut rng = rng();

    // Initialize encryption of `msg`, configure that the output will be a "SEIPDv1" encryption
    // container.
    let mut builder = MessageBuilder::from_bytes("", msg.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    // Add `encryption_subkey` as one recipient of the encrypted message
    builder
        .encrypt_to_key(&mut rng, &encryption_subkey)
        .unwrap();

    // Perform the actual encryption of the payload and put together the resulting encrypted message
    builder.to_vec(&mut rng).unwrap()
}

/// Interpret `msg` as an encrypted message and decrypt it (and optionally decompress one layer of
/// compression, if necessary).
///
/// Returns the payload of the inner message.
fn decrypt(ssk: &SignedSecretKey, msg: &[u8]) -> Vec<u8> {
    // Perform the actual decryption operation (which yields a new OpenPGP `Message` object)
    let mut decrypted = Message::from_bytes(msg)
        .expect("parse message")
        .decrypt(&"".into(), ssk)
        .expect("decrypt message");

    // If this decrypted message is compressed, decompress it
    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().expect("Message decompress");
    }

    // Read the cleartext data stream from the now decrypted (and optionally decompressed) message
    decrypted.as_data_vec().expect("Message as data")
}

/// Parse private key from either armored or binary format
pub fn read_secret_key(input: &[u8]) -> SignedSecretKey {
    let (key, _headers) = SignedSecretKey::from_reader_single(input).unwrap();

    // Check that the binding self-signatures for each component are valid
    key.verify().expect("Verify key");

    key
}

/// Parse public key from either armored or binary format
pub fn read_public_key(input: &[u8]) -> SignedPublicKey {
    let (cert, _headers) = SignedPublicKey::from_reader_single(input).unwrap();

    // Check that the binding self-signatures for each component are valid
    cert.verify().expect("Verify cert");

    cert
}
