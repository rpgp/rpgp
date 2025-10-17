/// Normally, we reject RSA keys >4 kbit.
/// However, with feature "malformed-artifact-compat" we handle up to 16 kbit RSA
#[cfg(feature = "malformed-artifact-compat")]
#[test]
fn test_large_rsa() {
    use pgp::{
        composed::{
            Deserializable, DetachedSignature, Message, MessageBuilder, SignedPublicKey,
            SignedSecretKey,
        },
        crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
        types::Password,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    const PLAIN: &str = "hello world";

    // -- load public key --

    let (pubkey, _) = SignedPublicKey::from_armor_file("tests/rsa8k/rsa8k.pub.asc").unwrap();

    // encrypt message to "pubkey"
    let msg = MessageBuilder::from_bytes(&[][..], PLAIN.as_bytes());
    let mut msg = msg.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
    // NOTE: encrypting to primary, this is "wrong" in terms of PGP semantics, but sufficient for testing
    msg.encrypt_to_key(&mut rng, &pubkey).unwrap();
    let enc = msg.to_vec(&mut rng).unwrap();

    // -- load private key --

    let (seckey, _) = SignedSecretKey::from_armor_file("tests/rsa8k/rsa8k.sec.asc").unwrap();

    // parse "enc" into a new message object
    let msg = Message::from_bytes(enc.as_slice()).unwrap();
    // NOTE: decrypting with primary, this is "wrong" in terms of PGP semantics, but sufficient for testing
    let mut dec = msg.decrypt(&Password::empty(), &seckey).unwrap();
    let plain = dec.as_data_string().unwrap();
    assert_eq!(PLAIN, plain);

    // produce data signature
    let sig = DetachedSignature::sign_text_data(
        &mut rng,
        &seckey.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        PLAIN.as_bytes(),
    )
    .unwrap();

    // verify data signature
    sig.verify(&pubkey.primary_key, PLAIN.as_bytes())
        .expect("verify ok");
}
