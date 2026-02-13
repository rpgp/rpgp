use pgp::{
    composed::{Deserializable, Message},
    types::EncryptionKey,
};

/// RPG-022
#[test]
fn rpg_022_message_from_armor_single_panic2() {
    // expected bug behavior:
    // thread '[..]' panicked at [..]/src/armor/reader.rs:489:13:
    // invalid state
    let bad_input: &[u8] = b"-----BEGIN PGP SIGNATURE-----\n00LL";
    let _ = Message::from_armor(bad_input);
}

/// RPG-019
#[test]
fn rpg_019_message_decrypt_with_password_panic1() {
    let bad_input: &[u8] = &[
        140, 159, 4, 1, 0, 0, 0, 167, 167, 167, 167, 167, 167, 167, 167, 0, 0, 0, 0, 0, 0, 0, 145,
        68, 32, 70, 73, 76, 69, 208, 0, 0, 0, 0, 227, 167, 167, 76, 69, 210, 69, 208, 210, 167,
        167, 167, 227, 167, 167, 76, 69, 210, 167, 167, 167, 167, 167, 167, 227, 167, 167, 76, 69,
        210, 69, 208, 210, 167, 167, 167, 227, 167, 167, 76, 69, 227, 167, 167, 76, 69, 1, 0, 0, 0,
        0, 0, 4, 184, 167, 167, 167, 227, 167, 167, 76, 69, 167, 167, 167, 167, 167, 167, 68, 32,
        70, 73, 76, 69, 208, 210, 167, 167, 167, 227, 167, 167, 76, 69, 210, 69, 208, 210, 167,
        167, 167, 227, 167, 167, 76, 69, 227, 167, 167, 69, 73, 76, 69, 208, 210, 167, 167, 167,
        227, 167, 167, 76, 69, 210, 69, 208, 210, 167, 167, 167, 227, 167, 167, 76, 69, 227, 167,
        167,
    ];
    let message = Message::from_bytes(bad_input).unwrap();

    // expected bug behavior
    // thread '<unnamed>' panicked at library/alloc/src/raw_vec.rs:545:5:
    // capacity overflow
    let _ = message.decrypt_with_password(&"password does not matter".into());
}

/// RPG-019
#[test]
fn rpg_019_message_decrypt_with_password_panic2() {
    let bad_input: &[u8] = &[
        0xc3, 0x20, 0x04, 0x01, 0x01, 0x02, 0x32, 0xf6, 0xe3, 0xff, 0xff, 0xac, 0xa7, 0xa7, 0xa7,
        0xff, 0xff, 0xa7, 0x26, 0xaf, 0x20, 0x4b, 0xaf, 0xa7, 0xa7, 0xa7, 0xa7, 0xd1, 0x22, 0xa7,
        0xa7, 0xa7, 0x00, 0xa7, 0xa7, 0xd1, 0x22, 0xff, 0xff, 0xff, 0xa7, 0x26, 0xaf, 0x20, 0x4b,
        0xaf,
    ];
    let message = Message::from_bytes(bad_input).unwrap();

    // note that for this crash, the password does matter
    // expected bug behavior
    // thread '[..]' panicked at [..]/src/crypto/sym.rs:265:52:
    // not implemented: CFB resync is not here
    let _ = message.decrypt_with_password(&"bogus_password".into());
}

/// RPG-016
/// Only present in 0.11, added as regression test
#[test]
fn rpg_016_message_parser_panic2() {
    // expected bug behavior:
    // thread '<unnamed>' panicked at 'assertion failed: length > 0', src/packet/many.rs:140:17:

    let bad_input: &[u8] = &[0xb7];
    let _ = Message::from_bytes(bad_input);
}

/// RPG-015
#[test]
fn rpg_015_cleartext_signed_message_from_armor_panic1() {
    let bad_input: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 80, 32, 83, 73, 71, 78, 69, 68, 32, 77,
        69, 83, 83, 65, 71, 69, 45, 45, 45, 45, 45, 10, 10, 22, 10, 45, 45, 45, 45, 45, 66, 69, 71,
        73, 78, 32, 80, 71, 80, 32, 83, 73, 71, 78, 65, 84, 85, 82, 69, 45, 45, 45, 45, 45, 10, 72,
    ];
    let _ = pgp::composed::CleartextSignedMessage::from_armor(bad_input);
}

/// RPG-015
#[test]
fn rgp_015_cleartext_signed_message_from_string_panic1() {
    // this triggers the same bug as the from_armor() case, but is more human readable

    let bad_input = "-----BEGIN PGP SIGNED MESSAGE-----\n\n-\n-----BEGIN PGP SIGNATURE-----\n-";
    let _ = pgp::composed::CleartextSignedMessage::from_string(bad_input);
}

/// RPG-015
#[test]
fn rpg_015_cleartext_signed_message_from_string_panic2() {
    let data = "-----BEGIN PGP SIGNED MESSAGE-----\n\r\nqq\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n-----BEGIN PGP SIGNATURE-----\n\n\n\n\n\n\n\n\n
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq-qqqqqqqqqqqqqqqq\0----BE\u{7}IN-D*'S-- \u{1}{\0\0\u{1}\0\0\0\0\0\0\0\0\0\0\0\0\0\0-----BEGIN PGP PRIVATE KEY BLOCK
-----\n-----CEGIN PGP-----BEGIN OPENSSH PRIVATE qqqKEY----- M-----BEGIN OPENSSH PRIVATE KEY---- KEY----- M[ESSA-----BEGIN PGP SIGNED MESSAGE-----GE\t-
--\0\0\0\0\0\0>ATE KEY B- M[ESSAGE\t0--\0\0\0\0\0\0>ATE KEY BLOCK----%\n-----\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0>>>>>>>>\0\0\0\0\"DE-----END PGP PRIVATE KEY BLOCK---------BEYGIN PGP M[ESSAGE\t---\0\0>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>qq>>>>>>>>>>>>>>>>>>>\t>>>>>>>PGP M[ESSAGE\t---\0\0>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
>>>>>>>>>[ESSAGE\tw:::::::";

    let _ = pgp::composed::CleartextSignedMessage::from_string(data);
}

/// RPG-015
#[test]
fn rpg_015_cleartext_signed_message_from_armor_panic2() {
    let data = vec![
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 80, 32, 83, 73, 71, 78, 69, 68, 32, 77,
        69, 83, 83, 65, 71, 69, 45, 45, 45, 45, 45, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 45,
        89, 45, 45, 45, 45, 45, 10, 10, 10, 10, 10, 10, 10, 10, 10, 45, 45, 45, 45, 45, 66, 69, 71,
        73, 78, 32, 80, 71, 80, 32, 83, 73, 71, 78, 65, 84, 85, 82, 69, 45, 45, 45, 45, 45, 10, 10,
        10, 10, 10, 26, 45, 45, 45, 45, 45, 45, 45, 10, 10, 86, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        45, 45, 69, 78, 68, 32, 68, 83, 65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 58,
        26, 10, 10, 10, 10, 10, 10, 10, 86, 10, 10, 0, 0, 0, 0, 58, 58, 58, 58, 58, 58, 58, 58, 58,
        58, 58, 58, 45, 0, 45, 45, 45, 45, 10, 10, 10, 10, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73,
        78, 32, 69, 67, 32, 80, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 71, 80, 32, 83, 73, 71, 78, 69, 68, 32, 77,
        69, 83, 83, 65, 71, 69, 45, 0, 13, 10, 247, 255, 15, 0, 45, 45, 45, 45, 45, 45, 45, 69, 78,
        68, 32, 69, 67, 32, 80, 82, 71, 80, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 189, 10, 73,
        86, 65, 84, 69, 45, 45, 45, 66, 187, 175, 73, 78, 32, 80, 71, 80, 32, 77, 69, 83, 83, 65,
        71, 69, 45, 45, 83, 83, 65, 71, 69, 45, 45, 45, 45, 45, 133, 133, 133, 133, 10, 10, 10, 10,
        10, 133, 133, 133, 64, 10, 86, 10, 10, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 7, 121, 0, 0, 0,
        0, 0, 45, 0, 0, 0, 45, 45, 0, 13, 10, 45, 45, 45, 45, 10, 13, 10, 10, 45, 45, 45, 10, 166,
    ];
    let _ = pgp::composed::CleartextSignedMessage::from_armor(&data[..]);
}

/// RPG-007
#[test]
fn rpg_007_message_parser_panic1() {
    let bad_input: &[u8] = &[0xff, 0x1];

    // expected behavior
    // [...] panicked at src/packet/many.rs:128:70:
    // range end index 1 out of range for slice of length 0
    let _ = Message::from_bytes(bad_input);
}

/// RPG-007
#[test]
fn rpg_007_message_from_armor_single_panic1() {
    let bad_input: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 80, 32, 77, 69, 83, 83, 65, 71, 69, 45,
        45, 45, 45, 45, 10, 54, 84, 54, 53, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 71, 80, 32, 77,
        69, 83, 83, 65, 71, 69, 45, 45, 45, 45, 45,
    ];

    // expected bug behavior
    // thread '<unnamed>' panicked at [..]/src/packet/many.rs:126:70:
    // range end index 62 out of range for slice of length 1
    let _ = Message::from_armor(bad_input);
}

// API removed
// /// RPG-017
// #[test]
// fn rpg_017_signed_public_key_as_unsigned_panic1() {
//     let bad_input: &[u8] = &[155, 4, 228, 4, 0, 4, 0];
//     let key = pgp::composed::SignedPublicKey::from_bytes(bad_input).unwrap();
//     // expected bug behavior:
//     // thread '<unnamed>' panicked at src/composed/signed_key/shared.rs:116:35:
//     // missing user ids
//     let _ = key.as_unsigned();
// }

/// RPG-021
/// Actual fix is in RustCrypto/RSA
#[test]
fn rpg_021_signed_secret_key_encrypt_panic1() {
    let bad_input: &[u8] = &[
        197, 159, 4, 159, 1, 0, 20, 2, 0, 61, 0, 0, 0, 64, 0, 201, 0, 197, 0, 1, 251, 213, 0, 201,
        0, 250, 196, 0, 197, 0, 197, 0, 197, 0, 201, 0, 197, 0, 197, 0, 201, 255, 255, 255, 255,
        255, 255, 255, 5, 205, 205, 205, 205, 43, 129, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 1, 1,
        161, 4, 0, 242, 143, 4, 4, 135, 6, 0, 0, 0, 0, 6, 0, 0, 0, 0, 242, 143, 4, 4, 0, 0, 0, 0,
        0, 0, 0, 2, 0, 0, 0, 1, 1, 1, 161, 4, 0, 143, 4, 4, 135, 6, 0, 0, 0, 0, 4, 0, 242, 143, 4,
        4, 135, 6, 0, 0, 0, 0, 0, 0, 0, 0, 242, 143, 4, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1,
        1, 143, 4, 4, 135, 6, 0, 0, 0, 0,
    ];

    // no particular meaning of this data
    let dummy_plaintext = vec![0u8; 128];

    // note, this is non-deterministic, but does not matter for reproduction
    let mut rng = rand::rng();

    let key = pgp::composed::SignedSecretKey::from_bytes(bad_input).unwrap();

    // expected bug behavior on --release:
    // thread '<unnamed>' panicked at [..]/rsa-0.9.6/src/algorithms/pkcs1v15.rs:51:39:
    // range end index 18446744073709551492 out of range for slice of length 5
    //
    // expected bug behavior on --debug:
    // thread 'signed_secret_key_encrypt_panic1' panicked at [..]/rsa-0.9.6/src/algorithms/pkcs1v15.rs:44:20:
    // attempt to subtract with overflow
    //
    // crash also happens with pgp::types::EskType::V3_4
    let _ciphertext = {
        key.primary_key.public_key().encrypt(
            &mut rng,
            dummy_plaintext.as_slice(),
            pgp::types::EskType::V6,
        )
    };
}

/// RPG-021
#[test]
fn rpg_021_signed_secret_key_encrypt_panic2() {
    let bad_input: &[u8] = &[
        0x97, 0x04, 0x00, 0x1a, 0x1a, 0x1a, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x29,
    ];
    // no particular meaning of this data
    // let dummy_plaintext = vec![0u8; 1];
    // note, this is non-deterministic, but does not matter for reproduction
    // let mut rng = rand::rng();
    let key = pgp::composed::SignedSecretKey::from_bytes(bad_input);
    assert!(key.is_err());
    // stricter parsing triggers checks earlier
    // // expected bug behavior:
    // // thread '[..]' panicked at [..]/src/crypto/x448.rs:149:75:
    // // 56
    // //
    // // crash also happens with pgp::types::EskType::V3_4
    // let _ciphertext = {
    //     key.encrypt(
    //         &mut rng,
    //         dummy_plaintext.as_slice(),
    //         pgp::types::EskType::V6,
    //     )
    // };
}

/// RPG-020
/// Actual fix is done in RustCrypto/RSA
#[test]
fn rpg_020_signed_secret_key_create_signature_panic1() {
    let bad_input: &[u8] = &[
        151, 3, 255, 251, 255, 63, 39, 254, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
    ];

    // let dummy_data: &[u8] = &[0];

    let res = pgp::composed::SignedSecretKey::from_bytes(bad_input);
    assert!(res.is_err());

    // // expected bug behavior:
    // // thread '<unnamed>' panicked at [..]/num-bigint-dig-0.8.4/src/algorithms/sub.rs:75:5:
    // // Cannot subtract b from a because b is larger than a.
    // let _ = key.create_signature(
    //     &Password::empty(),
    //     pgp::crypto::hash::HashAlgorithm::Sha256,
    //     dummy_data,
    // );
}

/// RPG-020
#[test]
fn rpg_020_signed_secret_key_create_signature_panic2() {
    let bad_input: &[u8] = &[
        0x97, 0x04, 0x00, 0x00, 0x08, 0x29, 0xc1, 0xfd, 0xff, 0x03, 0x03, 0x02, 0x08, 0x00, 0xf8,
        0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xf8, 0xf8, 0xff, 0x00, 0xff,
        0x00, 0xff, 0x00,
    ];
    // let dummy_data: &[u8] = &[0];
    let res = pgp::composed::SignedSecretKey::from_bytes(bad_input);
    assert!(res.is_err());
    // // expected bug behavior for --debug:
    // // thread [..] panicked at [..]/src/types/params/encrypted_secret.rs:155:48:
    // // attempt to subtract with overflow
    // //
    // // expected bug behavior for --release:
    // // thread '[..]' panicked at [..]/src/types/params/encrypted_secret.rs:155:39:
    // // assertion failed: mid <= self.len()
    // let _ = key.create_signature(
    //     &"pw".into(),
    //     pgp::crypto::hash::HashAlgorithm::Sha256,
    //     dummy_data,
    // );
}

/// RPG-020
#[test]
fn rpg_020_signed_secret_key_create_signature_oom_crash1() {
    let bad_input: &[u8] = &[
        0x97, 0x04, 0x00, 0x00, 0x08, 0x29, 0xc1, 0xfd, 0xff, 0x9f, 0x04, 0x8f, 0xe4, 0xff, 0xff,
        0xff, 0xff, 0x80, 0x8f, 0x8f, 0x8f, 0x00, 0x01, 0x00, 0x00, 0x00, 0xaf, 0xf8, 0x1b, 0x1b,
    ];
    // let dummy_data: &[u8] = &[0];
    let res = pgp::composed::SignedSecretKey::from_bytes(bad_input);

    assert!(res.is_err());
    // // expected bug behavior:
    // // memory allocation of 137438871552 bytes failed
    // let _ = key.create_signature(
    //     &"pw".into(),
    //     pgp::crypto::hash::HashAlgorithm::Sha256,
    //     dummy_data,
    // );
}

/// RPG-010
#[test]
fn rpg_010_standalone_signature_subtract_with_overflow1() {
    let bad_input: &[u8] = &[209, 3, 0, 252, 45];

    // expected bug behavior
    // thread '<unnamed>' panicked at src/packet/user_attribute.rs:165:41:
    // attempt to subtract with overflow
    let _ = pgp::composed::DetachedSignature::from_bytes(bad_input);
}

/// RPG-009
#[test]
fn rpg_009_message_from_bytes_subtract_with_overflow1() {
    let bad_input: &[u8] = &[187, 6, 227, 0, 255, 255, 255, 255, 255, 255, 255];

    // depends on "--debug" profile
    // expected bug behavior
    // thread '<unnamed>' panicked at src/packet/public_key_parser.rs:250:47:
    // attempt to subtract with overflow
    let _ = Message::from_bytes(bad_input);
}

/// RPG-009
#[test]
fn rpg_009_message_from_bytes_subtract_with_overflow2() {
    let bad_input: &[u8] = &[139, 4, 16, 0, 0, 0, 2, 0, 0];

    // depends on "--debug" profile
    // expected bug behavior
    // thread '<unnamed>' panicked at src/packet/signature/de.rs:391:25:
    // attempt to subtract with overflow
    let _ = Message::from_bytes(bad_input);
}

/// RPG-009
#[test]
fn rpg_009_message_from_bytes_subtract_with_overflow3() {
    let bad_input: &[u8] = &[151, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 113, 113];

    // depends on "--debug" profile
    // expected bug behavior
    // thread '<unnamed>' panicked at src/types/params/secret.rs:106:47:
    // attempt to subtract with overflow
    let _ = Message::from_bytes(bad_input);
}

#[test]
fn oom_signature_1() {
    let bad_input = [
        155, 6, 3, 72, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    let res = pgp::composed::DetachedSignature::from_bytes(&bad_input[..]);
    assert!(res.is_err());
}
