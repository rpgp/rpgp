use chacha20::ChaCha20Rng;
use rand::SeedableRng;

// Tests that check for backward compatibility with older versions of rpgp

#[test]
fn ecdh_roundtrip_with_rpgp_0_10() {
    // Encrypt/decrypt roundtrip to validate that there is no padding breakage between rPGP versions.

    // Context: rPGP versions before 0.11 couldn't handle "long padding" (that exceeds one block),
    // see https://github.com/rpgp/rpgp/pull/280

    // However, rPGP 0.12 - 0.13.1 emit "long padding" by default (see https://github.com/rpgp/rpgp/pull/307),
    // which older rPGP cannot unpad (and thus not decrypt).

    // To avoid incompatibility with the (erroneous) ecdh handling in rPGP <0.11, rPGP produces
    // "short padding" again, starting with 0.13.2

    // Note: We use AES128 in this test so that the encrypting party is able to use "long padding".

    const MSG: &[u8] = b"hello world";

    // a test-key with an ECDH(Curve25519) encryption subkey
    const KEYFILE: &str = "./tests/unit-tests/padding/alice.key";

    // 0.10 -> cur
    // let enc = encrypt_rpgp_0_10(MSG, KEYFILE);
    let enc = std::fs::read_to_string("./tests/unit-tests/padding/rpgp-0-10.enc.asc").unwrap();
    let dec = decrypt_rpgp_cur(&enc, KEYFILE);
    assert_eq!(dec, MSG, "0.10 -> cur");

    // cur -> 0.10
    let enc = encrypt_rpgp_cur(MSG, KEYFILE);
    // std::fs::write("./tests/unit-tests/padding/rpgp-current.enc.asc", &enc).unwrap();
    // let dec = decrypt_rpgp_0_10(&enc, KEYFILE);
    let enc_expected =
        std::fs::read_to_string("./tests/unit-tests/padding/rpgp-current.enc.asc").unwrap();
    assert_eq!(enc, enc_expected.replace("\r\n", "\n"), "cur -> 0.10");
    // assert_eq!(dec, MSG, "cur -> 0.10");

    // cur -> cur
    let enc = encrypt_rpgp_cur(MSG, KEYFILE);
    let dec = decrypt_rpgp_cur(&enc, KEYFILE);
    assert_eq!(dec, MSG, "cur -> cur");
}

fn decrypt_rpgp_cur(enc_msg: &str, keyfile: &str) -> Vec<u8> {
    use pgp::composed::Deserializable;

    let (enc_msg, _) = pgp::composed::Message::from_string(enc_msg).expect("decrypt_rpgp_cur");

    let (ssk, _headers) =
        pgp::composed::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let mut dec = enc_msg.decrypt(&"".into(), &ssk).unwrap();

    dec.as_data_vec().unwrap()
}

fn encrypt_rpgp_cur(msg: &'static [u8], keyfile: &str) -> String {
    use pgp::{
        composed::{ArmorOptions, Deserializable, MessageBuilder},
        crypto::sym::SymmetricKeyAlgorithm,
    };

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let (ssk, _headers) =
        pgp::composed::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let enc = &ssk.secret_subkeys[0];

    let mut builder =
        MessageBuilder::from_bytes("", msg).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
    builder.encrypt_to_key(&mut rng, &enc.public_key()).unwrap();
    builder
        .to_armored_string(&mut rng, ArmorOptions::default())
        .unwrap()
}
