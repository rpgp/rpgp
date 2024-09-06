use std::fs::File;

use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::packet::LiteralData;
use pgp::types::KeyVersion;
use pgp::{
    cleartext::CleartextSignedMessage, Deserializable, KeyType, Message, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const MSG: &str = "hello world\n";

// Test cases based on keys with new formats from RFC9580
const CASES_9580: &[&str] = &[
    ("tests/rfc9580/v6-25519-annex-a-4"), // TSK from RFC 9580 Annex A.4 (Ed25519/X25519)
    ("tests/rfc9580/v6-ed25519-x448"), // TSK using Ed25519/X448 (TODO: replace with Ed448/X448 once rPGP supports it)
    ("tests/rfc9580/v6-rsa"),          // TSK using RSA
    ("tests/rfc9580/v6-nistp"),        // TSK using NIST P-256
    ("tests/rfc9580/v4-ed25519-x25519"), // version 4 TSK using the RFC 9580 Ed25519/X25519 formats
];

// Test cases based on keys that don't use new formats from RFC9580
const CASES_PRE_9580: &[&str] = &[];

fn load_ssk(filename: &str) -> SignedSecretKey {
    let (mut iter, _) =
        pgp::composed::signed_key::from_reader_many(File::open(filename).unwrap()).expect("ok");
    let pos = iter.next().expect("some").expect("ok");

    pos.into_secret()
}

fn try_decrypt(keyfile: &str, msg_file: &str) {
    let ssk = load_ssk(keyfile);

    // load seipdv1 msg, decrypt
    let (message, _) = Message::from_armor_single(File::open(msg_file).unwrap()).expect("ok");
    let (dec, _) = message.decrypt(String::default, &[&ssk]).expect("decrypt");

    let decrypted =
        String::from_utf8(dec.get_literal().expect("literal").data().to_vec()).expect("utf8");

    assert_eq!(&decrypted, MSG);
}

#[test]
fn rfc9580_decrypt_seipdv1_msg() {
    for case in CASES_9580 {
        try_decrypt(
            &format!("{}/tsk.asc", case),
            &format!("{}/enc-seipdv1.msg", case),
        );
    }
}

#[test]
fn rfc9580_decrypt_seipdv2_msg() {
    for case in CASES_9580.iter().chain(CASES_PRE_9580.iter()) {
        try_decrypt(
            &format!("{}/tsk.asc", case),
            &format!("{}/enc-seipdv2.msg", case),
        );
    }
}

#[test]
fn rfc9580_verify_csf() {
    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let csffile = format!("{}/csf.msg", case);

        let ssk = load_ssk(&keyfile);
        let spk = SignedPublicKey::from(ssk.clone());

        // load+verify csf msg
        let (csf, _) =
            CleartextSignedMessage::from_armor(File::open(csffile).unwrap()).expect("csf loaded");

        csf.verify(&spk).expect("verify ok");
    }
}

#[test]
fn rfc9580_seipdv1_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());
        let enc_subkey = &spk.public_subkeys.first().unwrap().key;

        let lit = LiteralData::from_bytes("".into(), MSG.as_bytes());
        let msg = Message::Literal(lit);

        // SEIPDv1 encrypt/decrypt roundtrip
        let enc = msg
            .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, &[enc_subkey])
            .expect("encrypt");

        let (dec, _) = enc.decrypt(String::default, &[&ssk]).expect("decrypt");
        let Message::Literal(lit) = dec else {
            panic!("expecting literal data");
        };

        assert_eq!(String::from_utf8_lossy(lit.data()), MSG);
    }
}

#[test]
fn rfc9580_seipdv2_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580.iter().chain(CASES_PRE_9580.iter()) {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());
        let enc_subkey = &spk.public_subkeys.first().unwrap().key;

        let lit = LiteralData::from_bytes("".into(), MSG.as_bytes());
        let msg = Message::Literal(lit);

        // SEIPDv2 encrypt/decrypt roundtrip
        let enc = msg
            .encrypt_to_keys_seipdv2(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb,
                0x06, // 2^12 bytes
                &[enc_subkey],
            )
            .expect("encrypt");

        let (dec, _) = enc.decrypt(String::default, &[&ssk]).expect("decrypt");
        let Message::Literal(lit) = dec else {
            panic!("expecting literal data");
        };

        assert_eq!(String::from_utf8_lossy(lit.data()), MSG);
    }
}

#[test]
fn rfc9580_roundtrip_csf() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());

        // roundtrip sign+verify csf
        let csf = CleartextSignedMessage::sign(&mut rng, MSG, &ssk, String::default).expect("sign");
        csf.verify(&spk).expect("verify");
    }
}

#[test]
fn rfc9580_roundtrip_sign_verify_inline_msg() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());

        let lit = LiteralData::from_bytes("".into(), MSG.as_bytes());
        let msg = Message::Literal(lit);

        // roundtrip sign+verify inline msg
        let signed = msg
            .sign(&mut rng, &ssk, String::default, HashAlgorithm::default())
            .expect("sign");

        signed.verify(&spk).expect("verify");
    }
}

#[test]
fn rfc9580_legacy_25519_illegal_in_v6() {
    // Ensure that rPGP rejects v6 EdDSA legacy or ECDH(Curve25519) keys

    // "The deprecated OIDs for Ed25519Legacy and Curve25519Legacy are used only in version 4 keys
    // and signatures. [..] Implementations MUST NOT accept or generate version 6 key material
    // using the deprecated OIDs."
    //
    // See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.2-6

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    // -- Try (and fail) to load a v6/legacy key --
    let key_file = File::open("tests/rfc9580/v6-legacy_illegal/tsk.asc").unwrap();

    let (mut iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");
    let res = iter.next().expect("result");

    // we expect an error about the illegal legacy parameters in a v6 key
    assert!(res.is_err());

    // -- Create a v6 ed25519 legacy signing key, expect failure --
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::EdDSALegacy)
        .version(KeyVersion::V6)
        .can_sign(true)
        .primary_user_id("Me <me@example.com>".into());
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let res = secret_key_params.generate(&mut rng);

    assert!(res.is_err());

    // -- Create a v6 curve 25519 legacy encryption key, expect failure --
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::ECDH(ECCCurve::Curve25519))
        .version(KeyVersion::V6)
        .can_encrypt(true)
        .primary_user_id("Me <me@example.com>".into());
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let res = secret_key_params.generate(&mut rng);

    assert!(res.is_err());
}
