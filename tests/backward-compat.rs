use rand::SeedableRng;
use rand_chacha::ChaChaRng;

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

    // 0.10 -> 0.10
    let enc = encrypt_rpgp_0_10(MSG, KEYFILE);
    let dec = decrypt_rpgp_0_10(&enc, KEYFILE);
    assert_eq!(dec, MSG, "0.10 -> 0.10");

    // 0.10 -> cur
    let enc = encrypt_rpgp_0_10(MSG, KEYFILE);
    let dec = decrypt_rpgp_cur(&enc, KEYFILE);
    assert_eq!(dec, MSG, "0.10 -> cur");

    // cur -> 0.10
    let enc = encrypt_rpgp_cur(MSG, KEYFILE);
    let dec = decrypt_rpgp_0_10(&enc, KEYFILE);
    assert_eq!(dec, MSG, "cur -> 0.10");

    // cur -> cur
    let enc = encrypt_rpgp_cur(MSG, KEYFILE);
    let dec = decrypt_rpgp_cur(&enc, KEYFILE);
    assert_eq!(dec, MSG, "cur -> cur");
}

fn decrypt_rpgp_0_10(enc_msg: &str, keyfile: &str) -> Vec<u8> {
    use rpgp_0_10::Deserializable;

    let (enc_msg, _) = rpgp_0_10::Message::from_string(enc_msg).unwrap();

    let (ssk, _headers) =
        rpgp_0_10::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let (mut dec, _) = enc_msg
        .decrypt(|| "".to_string(), &[&ssk])
        .expect("decrypt_rpgp_0_10");
    let inner = dec.next().unwrap().unwrap();

    inner.get_literal().unwrap().data().to_vec()
}

fn decrypt_rpgp_cur(enc_msg: &str, keyfile: &str) -> Vec<u8> {
    use pgp::Deserializable;

    let (enc_msg, _) = pgp::Message::from_string(enc_msg).expect("decrypt_rpgp_cur");

    let (ssk, _headers) =
        pgp::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let (dec, _) = enc_msg.decrypt(|| "".to_string(), &[&ssk]).unwrap();

    dec.get_literal().unwrap().data().to_vec()
}

fn encrypt_rpgp_0_10(msg: &[u8], keyfile: &str) -> String {
    use rpgp_0_10::crypto::sym::SymmetricKeyAlgorithm;
    use rpgp_0_10::Deserializable;

    let mut rng = ChaChaRng::from_seed([0u8; 32]);

    let lit = rpgp_0_10::packet::LiteralData::from_bytes((&[]).into(), msg);
    let msg = rpgp_0_10::Message::Literal(lit);

    let (ssk, _headers) =
        rpgp_0_10::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let enc = &ssk.secret_subkeys[0];

    let enc_msg = msg
        .encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[enc])
        .unwrap();

    enc_msg.to_armored_string(None).unwrap()
}

fn encrypt_rpgp_cur(msg: &[u8], keyfile: &str) -> String {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::{ArmorOptions, Deserializable};

    let mut rng = ChaChaRng::from_seed([0u8; 32]);

    let lit = pgp::packet::LiteralData::from_bytes((&[]).into(), msg);
    let msg = pgp::Message::Literal(lit);

    let (ssk, _headers) =
        pgp::SignedSecretKey::from_armor_single(std::fs::File::open(keyfile).unwrap())
            .expect("failed to read key");

    let enc = &ssk.secret_subkeys[0];

    let enc_msg = msg
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[enc])
        .unwrap();

    enc_msg.to_armored_string(ArmorOptions::default()).unwrap()
}
