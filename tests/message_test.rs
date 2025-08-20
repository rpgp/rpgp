extern crate rand;
#[macro_use]
extern crate pretty_assertions;
extern crate serde_json;
#[macro_use]
extern crate serde;
extern crate pgp;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use std::fs::File;

use pgp::{
    composed::{
        CleartextSignedMessage, Deserializable, Message, PlainSessionKey, SignedPublicKey,
        SignedSecretKey,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    types::{KeyDetails, KeyId, Password},
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Testcase {
    typ: Option<String>,
    decrypt_key: String,
    passphrase: String,
    verify_key: Option<String>,
    filename: Option<String>,
    timestamp: Option<u64>,
    textcontent: Option<String>,
    keyid: Option<String>,
}

fn test_parse_msg(entry: &str, base_path: &str, _is_normalized: bool) {
    let _ = pretty_env_logger::try_init();

    // TODO: verify filename
    let n = format!("{base_path}/{entry}");
    let mut file = File::open(&n).unwrap_or_else(|_| panic!("no file: {}", &n));

    let details: Testcase = serde_json::from_reader(&mut file).unwrap();
    info!(
        "Testcase: {}",
        serde_json::to_string_pretty(&details).unwrap()
    );

    let mut decrypt_key_file =
        File::open(format!("{}/{}", base_path, details.decrypt_key)).unwrap();
    let (decrypt_key, _headers) = SignedSecretKey::from_armor_single(&mut decrypt_key_file)
        .expect("failed to read decryption key");
    decrypt_key
        .verify_bindings()
        .expect("invalid decryption key");

    let decrypt_id = hex::encode(decrypt_key.legacy_key_id());

    info!("decrypt key (ID={})", &decrypt_id);
    if let Some(id) = &details.keyid {
        assert_eq!(id, &decrypt_id, "invalid keyid");
    }

    let verify_key = if let Some(verify_key_str) = details.verify_key.clone() {
        let mut verify_key_file = File::open(format!("{base_path}/{verify_key_str}")).unwrap();
        let (verify_key, _headers) = SignedPublicKey::from_armor_single(&mut verify_key_file)
            .expect("failed to read verification key");
        verify_key
            .verify_bindings()
            .expect("invalid verification key");

        let verify_id = hex::encode(verify_key.legacy_key_id());
        info!("verify key (ID={})", &verify_id);
        Some(verify_key)
    } else {
        None
    };

    let file_name = entry.replace(".json", ".asc");
    let cipher_file_path = format!("{base_path}/{file_name}");
    // let cipher_file = File::open(&cipher_file_path).unwrap();

    let (message, _headers) =
        Message::from_armor_file(cipher_file_path).expect("failed to parse message");
    info!("message: {:?}", &message);

    match &message {
        Message::Encrypted { .. } => {
            let decrypted = message
                .decrypt(&details.passphrase.into(), &decrypt_key)
                .expect("failed to init decryption");

            let mut msg = decrypted.decompress().expect("compression");
            dbg!(&msg);
            let data = msg.as_data_string().unwrap();

            // TODO: figure out how to do roundtrips
            // serialize and check we get the same thing
            // let serialized = decrypted.to_armored_bytes(None.into()).unwrap();
            // // and parse them again
            // let (decrypted2, _headers) =
            //     Message::from_armor(&serialized[..]).expect("failed to parse round2");
            // assert_eq!(decrypted, decrypted2);

            assert_eq!(data, details.textcontent.unwrap_or_default());

            if let Some(verify_key) = verify_key {
                msg.verify(&verify_key.primary_key)
                    .expect("message verification failed");
            }
        }
        Message::Signed { reader, .. } => {
            println!("signature: {:?}", reader.signature());
        }
        _ => {
            // TODO: some other checks?
            panic!("this test should not have anything else?");
        }
    }

    // TODO: how to roundtrip?
    // // serialize and check we get the same thing
    // let serialized = message.to_armored_string(Some(&headers).into()).unwrap();
    // if is_normalized {
    //     let mut cipher_file = File::open(&cipher_file_path).unwrap();
    //     let mut expected_bytes = String::new();
    //     cipher_file.read_to_string(&mut expected_bytes).unwrap();
    //     // normalize read in line endings to unix
    //     assert_eq!(serialized, expected_bytes.replace("\r\n", "\n"));
    // }
    // // and parse them again
    // let (message2, headers2) =
    //     Message::from_armor(serialized.as_bytes()).expect("failed to parse round2");
    // assert_eq!(headers, headers2);
    // assert_eq!(message, message2);
}

macro_rules! msg_test {
    ($name:ident, $pos:expr, $normalized:expr) => {
        #[test]
        fn $name() {
            test_parse_msg(
                &format!("{}.json", $pos),
                "./tests/openpgp-interop/testcases/messages",
                $normalized,
            );
        }
    };
}

// RSA
msg_test!(msg_gnupg_v1_001, "gnupg-v1-001", false);
// Elgamal
// msg_test!(msg_gnupg_v1_002, "gnupg-v1-002", true);
// RSA
msg_test!(msg_gnupg_v1_003, "gnupg-v1-003", false);

msg_test!(msg_gnupg_v1_4_11_001, "gnupg-v1-4-11-001", true);
msg_test!(msg_gnupg_v1_4_11_002, "gnupg-v1-4-11-002", false);
msg_test!(msg_gnupg_v1_4_11_003, "gnupg-v1-4-11-003", true);
msg_test!(msg_gnupg_v1_4_11_004, "gnupg-v1-4-11-004", true);
msg_test!(msg_gnupg_v1_4_11_005, "gnupg-v1-4-11-005", true);
msg_test!(msg_gnupg_v1_4_11_006, "gnupg-v1-4-11-006", false);
msg_test!(msg_gnupg_v2_0_17_001, "gnupg-v2-0-17-001", true);
msg_test!(msg_gnupg_v2_0_17_002, "gnupg-v2-0-17-002", false);
msg_test!(msg_gnupg_v2_0_17_003, "gnupg-v2-0-17-003", true);
msg_test!(msg_gnupg_v2_0_17_004, "gnupg-v2-0-17-004", true);
msg_test!(msg_gnupg_v2_0_17_005, "gnupg-v2-0-17-005", true);
msg_test!(msg_gnupg_v2_0_17_006, "gnupg-v2-0-17-006", true);
// parsing error
// ECDH key - nist p256
// msg_test!(msg_gnupg_v2_1_5_001, "gnupg-v2-1-5-001", true);

// parsing error
// ECDH key - nist p384
// msg_test!(msg_gnupg_v2_1_5_002, "gnupg-v2-1-5-002", true);
// parsing error
// ECDH key - nist p512
// msg_test!(msg_gnupg_v2_1_5_003, "gnupg-v2-1-5-003", true);

msg_test!(msg_gnupg_v2_10_001, "gnupg-v2-10-001", true);
msg_test!(msg_gnupg_v2_10_002, "gnupg-v2-10-002", true);
msg_test!(msg_gnupg_v2_10_003, "gnupg-v2-10-003", true);
msg_test!(msg_gnupg_v2_10_004, "gnupg-v2-10-004", false);
msg_test!(msg_gnupg_v2_10_005, "gnupg-v2-10-005", true);
msg_test!(msg_gnupg_v2_10_006, "gnupg-v2-10-006", true);
msg_test!(msg_gnupg_v2_10_007, "gnupg-v2-10-007", true);

// ECDH
// msg_test!(msg_e2e_001, "e2e-001", true);
// ECDH
// msg_test!(msg_e2e_002, "e2e-001", true);

msg_test!(msg_pgp_10_0_001, "pgp-10-0-001", false);
msg_test!(msg_pgp_10_0_002, "pgp-10-0-002", false);
msg_test!(msg_pgp_10_0_003, "pgp-10-0-003", false);
msg_test!(msg_pgp_10_0_004, "pgp-10-0-004", false);
msg_test!(msg_pgp_10_0_005, "pgp-10-0-005", false);
msg_test!(msg_pgp_10_0_006, "pgp-10-0-006", false);
msg_test!(msg_pgp_10_0_007, "pgp-10-0-007", false);

msg_test!(msg_camellia128_001, "camellia128-001", false);
msg_test!(msg_camellia192_001, "camellia192-001", false);
msg_test!(msg_camellia256_001, "camellia256-001", false);

// ECDH
// msg_test!(msg_openkeychain_001, "openkeychain-001", true);

msg_test!(msg_openpgp_001, "openpgp-001", false);

macro_rules! msg_test_js {
    ($name:ident, $pos:expr, $normalized:expr) => {
        #[test]
        fn $name() {
            test_parse_msg(&format!("{}.json", $pos), "./tests/openpgpjs", $normalized);
        }
    };
}

msg_test_js!(msg_openpgpjs_x25519, "x25519", true);

#[test]
fn msg_partial_body_len() {
    let msg_file = "./tests/partial.asc";
    Message::from_armor_file(msg_file).expect("failed to parse message");
}

#[test]
fn msg_regression_01() {
    let msg_file = "./tests/regression-01.asc";
    Message::from_armor_file(msg_file).expect("failed to parse message");
}

#[test]
fn msg_large_indeterminate_len() {
    let _ = pretty_env_logger::try_init();

    let msg_file = "./tests/indeterminate.asc";
    let (message, _headers) = Message::from_armor_file(msg_file).expect("failed to parse message");

    let mut key_file = File::open("./tests/openpgpjs/x25519.sec.asc").unwrap();
    let (decrypt_key, _headers) =
        SignedSecretKey::from_armor_single(&mut key_file).expect("failed to parse key");

    let decrypted = message
        .decrypt(&"moon".into(), &decrypt_key)
        .expect("failed to decrypt message");

    let mut msg = decrypted.decompress().unwrap();
    let raw = msg.as_data_string().unwrap();

    assert_eq!(
        raw,
        "Content-Type: text/plain; charset=us-ascii
Autocrypt-Gossip: addr=deltabot@codespeak.net; keydata=
  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
  I=
Autocrypt-Gossip: addr=holger@merlinux.eu; keydata=
  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
  1CvHBWNRmnPMaFMeSpgJ

test1
"
    );
}

#[test]
fn msg_literal_signature() {
    let (pkey, _) = SignedPublicKey::from_armor_single(
        File::open("./tests/autocrypt/alice@autocrypt.example.pub.asc").unwrap(),
    )
    .unwrap();
    let (msg, _) = Message::from_armor_file("./tests/literal-text-signed.asc")
        .expect("failed to parse message");

    let mut msg = msg.decompress().unwrap();
    msg.verify_read(&pkey).unwrap();
}

#[test]
fn binary_msg_password() {
    // encrypted README.md using gpg
    let message = Message::from_file("./tests/binary_password.pgp").unwrap();
    let decrypted = message.decrypt_with_password(&"1234".into()).unwrap();
    let decompressed = decrypted.decompress().unwrap();

    assert!(decompressed.is_literal());
    assert_eq!(
        decompressed.literal_data_header().unwrap().file_name(),
        "README.md"
    );
}

/// Tests decryption of a message that uses the Wildcard KeyID "0000000000000000" is its PKESK.
///
/// Test message comes from the "Recipient IDs" test in the OpenPGP interoperability test suite.
#[test]
fn wildcard_id_decrypt() {
    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/draft-bre-openpgp-samples-00/bob.sec.asc").unwrap(),
    )
    .unwrap();

    let (msg, _) = Message::from_armor_file("./tests/wildcard.msg").expect("msg");

    let mut dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");

    let decrypted = dec.as_data_string().unwrap();
    assert_eq!(&decrypted, "Hello World :)");
}

/// Tests decryption of a message that is encrypted to a symmetrical secret.
#[test]
fn skesk_decrypt() {
    let (msg, _) = Message::from_armor_file("./tests/sym-password.msg").expect("msg");

    let mut dec = msg
        .decrypt_with_password(&Password::from("password"))
        .expect("decrypt_with_password");

    let decrypted = dec.as_data_string().unwrap();
    assert_eq!(&decrypted, "hello world");
}

/// Tests decryption of a message that was encrypted by PGP 6.5.8 to a v3 RSA key.
/// The message uses a historical SED encryption container.
#[test]
fn pgp6_decrypt() {
    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/pgp6/alice.sec.asc").unwrap(),
    )
    .unwrap();

    let (msg, _) = Message::from_armor_file("./tests/pgp6/hello.msg").expect("msg");
    dbg!(&msg);

    let dec = msg
        .decrypt_legacy(&Password::empty(), &skey)
        .expect("decrypt");
    let mut dec = dec.decompress().expect("decompress");

    let decrypted = dec.as_data_string().unwrap();
    assert_eq!(&decrypted, "hello world\n");
}

/// Tests that decompressing compression quine does not result in stack overflow.
/// quine.out comes from <https://mumble.net/~campbell/misc/pgp-quine/>
/// See <https://mumble.net/~campbell/2013/10/08/compression> for details.
#[test]
fn test_compression_quine() {
    // Public key does not matter as the message is not signed.
    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
    )
    .unwrap();
    let pkey = skey.public_key();

    let msg = Message::from_file("./tests/quine.out").unwrap();
    let mut msg = msg.decompress().unwrap();
    let res = msg.as_data_vec().unwrap();
    assert_eq!(res.len(), 176);

    let msg = Message::from_file("./tests/quine.out").unwrap();
    assert!(msg.verify(pkey).is_err());
}

#[test]
fn test_text_signature_normalization() {
    // Test verifying an inlined signed message.
    //
    // The signature type is 0x01 ("Signature of a canonical text document").
    //
    // The literal data packet (which is in binary mode) contains the output of:
    // echo -en "foo\nbar\r\nbaz"
    //
    // RFC 9580 mandates that the hash for signature type 0x01 has to be calculated over normalized line endings,
    // so the hash for this message is calculated over "foo\r\nbar\r\nbaz".
    //
    // So it must also be verified against a hash digest over this normalized format.
    let (mut signed_msg, _header) =
        Message::from_armor_file("./tests/unit-tests/text_signature_normalization.msg").unwrap();

    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/unit-tests/text_signature_normalization_alice.key").unwrap(),
    )
    .unwrap();

    // Manually find the signing subkey
    let signing = skey
        .secret_subkeys
        .iter()
        .find(|key| {
            key.legacy_key_id() == KeyId::from([0x64, 0x35, 0x7E, 0xB6, 0xBB, 0x55, 0xDE, 0x12])
        })
        .unwrap();

    // And transform it into a public subkey for signature verification
    let verify = signing.public_key();

    // verify the signature with alice's signing subkey
    signed_msg
        .verify_read(&verify)
        .expect("signature seems bad");
}

// Sample Version 6 Certificate (Transferable Public Key)
// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat
const ANNEX_A_3: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----";

// Sample Version 6 Secret Key (Transferable Secret Key)
// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key
const ANNEX_A_4: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----";

/// Verify Cleartext Signed Message
///
/// Test data from RFC 9580, see
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-cleartext-signed-mes
#[test]
fn test_v6_annex_a_6() {
    let (ssk, _) = SignedPublicKey::from_string(ANNEX_A_3).expect("SSK from armor");

    let msg = "-----BEGIN PGP SIGNED MESSAGE-----

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----";

    let (msg, _) = CleartextSignedMessage::from_string(msg).unwrap();

    msg.verify(&ssk).expect("verify");
}

/// Verify Inline Signed Message
///
/// Test data from RFC 9580, see
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-inline-signed-messag
#[test]
fn test_v6_annex_a_7() {
    let (ssk, _) = SignedPublicKey::from_string(ANNEX_A_3).expect("SSK from armor");

    let msg = "-----BEGIN PGP MESSAGE-----

xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk
1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv
bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k
bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l
JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ
b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj
FtCgazStmsuOXF9SFQE=
-----END PGP MESSAGE-----";

    let (mut msg, _) = Message::from_string(msg).unwrap();

    msg.verify_read(&ssk).expect("verify");
}

/// Decrypt an X25519-AEAD-OCB Encrypted Packet Sequence
///
/// Test data from RFC 9580, see
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-x25519-aead-ocb-encr
#[test]
fn test_v6_annex_a_8() {
    let (ssk, _) = SignedSecretKey::from_string(ANNEX_A_4).expect("SSK from armor");

    // A.8. Sample X25519-AEAD-OCB Decryption
    let msg = "-----BEGIN PGP MESSAGE-----

wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO
WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS
aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l
yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo
bhF30A+IitsxxA==
-----END PGP MESSAGE-----";

    let (message, _) = Message::from_string(msg).expect("ok");
    let mut dec = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let decrypted = dec.as_data_string().unwrap();
    assert_eq!(&decrypted, "Hello, world!");
}

#[test]
fn test_invalid_partial_messages() {
    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    // 512 bytes, f256 p128 f128
    let (message, _) =
        Message::from_armor_file("./tests/partial_invalid_two_fixed.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );

    // 512 bytes, p512 f0 f0
    let (message, _) =
        Message::from_armor_file("./tests/partial_invalid_two_fixed_empty.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );

    // 512 bytes, p512 f1
    let (message, _) =
        Message::from_armor_file("./tests/partial_invalid_short_last.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string()
            .contains("Fixed chunk was shorter than expected"),
        "found error: {err}"
    );
}

#[test]
fn test_invalid_multi_message() {
    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    // compressed, followed by literal
    let (message, _) = Message::from_armor_file("./tests/multi_message_1.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    dbg!(&msg);
    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    let err_string = err.to_string();
    assert!(
        err_string.contains("unexpected trailing") && err_string.contains("LiteralData"),
        "found error: {err_string}"
    );
}

#[test]
fn test_packet_excess_data() {
    // Message from the test "Packet excess consumption" in the interop suite.

    // The message contains extra tailing data inside the compressed packet, which the decompressor
    // ignores. The test checks that the consumer skips this data and successfully processes the
    // message.

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    // 100kbyte of excess trailing data in the compressed packet
    let (message, _) = Message::from_armor_file("./tests/tests/excess_100k.msg").expect("ok");

    dbg!(&message);
    let msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");
    let mut msg = msg.decompress().unwrap();

    dbg!(&msg);
    let data = msg.as_data_vec().unwrap();

    assert_eq!(&data, b"Hello World :)");
}

#[test]
fn test_two_messages() {
    // "Two messages, concatenated" from the OpenPGP interoperability test suite

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) = Message::from_armor_file("./tests/two_messages.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let res = msg.as_data_string();
    dbg!(&res);

    let err = res.unwrap_err();
    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );
}

#[test]
fn test_two_literals_first_compressed_no_decompression() {
    // "Two literals, 1st compressed 1 times" from the OpenPGP interoperability test suite

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) =
        Message::from_armor_file("./tests/two_literals_first_compressed.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );
}

#[test]
fn test_two_literals_first_compressed_two_times() {
    // "Two literals, 1st compressed 2 times" from the OpenPGP interoperability test suite

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) =
        Message::from_armor_file("./tests/two_literals_first_compressed_two_times.asc")
            .expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let err = msg.as_data_vec().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );
}

#[test]
fn test_two_literals_first_compressed_explicit_decompression() {
    // "Two literals, 1st compressed 1 times" from the OpenPGP interoperability test suite,
    // Explicitly decompressing the compressed packet.

    // FIXME: this test should probably error somewhere?

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) =
        Message::from_armor_file("./tests/two_literals_first_compressed.asc").expect("ok");

    dbg!(&message);
    let msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let mut msg = msg.decompress().unwrap();

    let err = msg.as_data_string().unwrap_err();
    dbg!(&err);

    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );
}

#[test]
fn test_two_literals_first_compressed_two_times_explicit_decompression() {
    // "Two literals, 1st compressed 2 times" from the OpenPGP interoperability test suite,
    // Explicitly decompressing the compressed packet.

    // FIXME: this test should probably error somewhere?

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) =
        Message::from_armor_file("./tests/two_literals_first_compressed_two_times.asc")
            .expect("ok");

    dbg!(&message);
    let msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let msg = msg.decompress().unwrap();
    dbg!(&msg);
    let mut msg = msg.decompress().unwrap();
    dbg!(&msg);

    let res = msg.as_data_string();
    dbg!(&res);

    let err = res.unwrap_err();
    assert!(
        err.to_string().contains("unexpected trailing"),
        "found error: {err}"
    );
}

#[test]
fn test_literal_eating_mdc() {
    // "Literal eating MDC" from the OpenPGP interoperability test suite

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (message, _) = Message::from_armor_file("./tests/literal_eating_mdc.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let res = msg.as_data_vec();
    dbg!(&res);

    let err = res.unwrap_err();
    assert!(
        err.to_string()
            .contains("Fixed chunk was shorter than expected"),
        "found error: {err}"
    );
}

#[test]
fn test_unknown_hash() {
    pretty_env_logger::try_init().ok();
    let (msg, _) = Message::from_armor_file("tests/sigs/unknown_hash.sig.asc").unwrap();
    dbg!(&msg);

    let mut msg = msg
        .decrypt_with_session_key(PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            key: hex::decode("0A62FC3D10FA134E8C3C915C68AA4B6C6E081D68A9ED1578735AC4743D0381F8")
                .unwrap()
                .into(),
        })
        .expect("failed to decrypt");

    dbg!(&msg);
    let content = msg.as_data_string().expect("failed to read");
    assert_eq!(content, "Encrypted, signed message.");
}

#[test]
fn test_unknown_one_pass() {
    pretty_env_logger::try_init().ok();
    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    let (msg, _) = Message::from_armor_file("tests/sigs/unknown_one_pass.sig.asc").unwrap();
    dbg!(&msg);

    let mut msg = msg
        .decrypt(&Password::empty(), &ssk)
        .expect("failed to decrypt");

    dbg!(&msg);
    let content = msg.as_data_string().expect("failed to read");
    assert_eq!(content, "Encrypted, signed message.");
    dbg!(&msg);
}

#[test]
fn test_signature_leniency() {
    // Test graceful handling of signatures with unknown elements.
    // Test vectors from "Messages with unknown packets" in OpenPGP interoperability test suite.

    pretty_env_logger::try_init().ok();

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
            .expect("ssk");

    // "PKESK3 SEIPDv1 [OPS3[H99] Literal Sig4[H99]]" from the OpenPGP interoperability test suite
    let (message, _) = Message::from_armor_file("./tests/message_other_hash.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let res = msg.as_data_vec();
    dbg!(&res);

    assert!(res.is_ok());

    // "PKESK3 SEIPDv1 [OPS3[P99] Literal Sig4[P99]]" from the OpenPGP interoperability test suite
    let (message, _) = Message::from_armor_file("./tests/message_other_pub_algo.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let res = msg.as_data_vec();
    dbg!(&res);

    assert!(res.is_ok());

    // "PKESK3 SEIP [OPS23 OPS3 Literal Sig4 Sig23]" from the OpenPGP interoperability test suite
    let (message, _) =
        Message::from_armor_file("./tests/message_future_signature.asc").expect("ok");

    dbg!(&message);
    let mut msg = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let res = msg.as_data_vec();
    dbg!(&res);

    assert!(res.is_ok());
}

#[test]
fn test_packet_leniency() {
    // Tests graceful handling of a certificate with an unknown packet.
    // Test vector "P U UB S SB X B" from "Perturbed certificates" in OpenPGP interoperability test suite.

    pretty_env_logger::try_init().ok();

    let (key, _) = SignedPublicKey::from_armor_file("./tests/perturbed.pub.asc").unwrap();
    dbg!(&key);
}

// Tests graceful handling of a certificates with a subkey that has unknown features.
// Test vectors from "Mock PQ subkey" in OpenPGP interoperability test suite.

#[test]
fn test_mock_pq_cert_leniency_unkown_algo_mpi() {
    pretty_env_logger::try_init().ok();
    let (key, _) =
        SignedPublicKey::from_armor_file("./tests/mock_pq/unknown_algo_mpi.pub.asc").unwrap();
    dbg!(&key);
}

#[test]
fn test_mock_pq_cert_leniency_ecdsa_opaque() {
    pretty_env_logger::try_init().ok();
    let (key, _) =
        SignedPublicKey::from_armor_file("./tests/mock_pq/ecdsa_opaque_small.pub.asc").unwrap();
    dbg!(&key);
}
#[test]
fn test_mock_pq_cert_leniency_eddsa_opaque() {
    pretty_env_logger::try_init().ok();
    let (key, _) =
        SignedPublicKey::from_armor_file("./tests/mock_pq/eddsa_opaque_small.pub.asc").unwrap();
    dbg!(&key);
}
#[test]
fn test_mock_pq_cert_leniency_ecdh_opaque() {
    pretty_env_logger::try_init().ok();
    let (key, _) =
        SignedPublicKey::from_armor_file("./tests/mock_pq/ecdh_opaque_small.pub.asc").unwrap();
    dbg!(key);
}

#[test]
fn fuzz_msg_reader() {
    // those are fuzzer-generated "messages" that each contain a nonsensical series of packets
    // (surely with nonsensical package contents, as well)
    pretty_env_logger::try_init().ok();

    for file in [
        // OPS SIG PKESK SED BAD
        "./tests/fuzz/minimized-from-7585e756306047aba2218ebf70b24c6373e82e2a",
        // OPS SKESK SED
        "./tests/fuzz/minimized-from-82b02bbac39a10c7b98d020f78153ffb75c94607",
    ] {
        let _ = Message::from_file(file).unwrap().as_data_vec();
    }
}

#[test]
fn fuzz_msg_reader_fail() {
    // those are fuzzer-generated "messages" that each contain a nonsensical series of packets
    // (surely with nonsensical package contents, as well)
    pretty_env_logger::try_init().ok();

    for file in [
        // many OPS, followed by some odd packet(s)
        "./tests/fuzz/crash-1b1482d11c52075aabfc75256626a56c607787f3",
        "./tests/fuzz/minimized-from-e2a02fea22523e47a4d74b66bda8f455533bcfbb",
    ] {
        let _ = Message::from_file(file).unwrap_err();
    }
}

#[test]
fn message_parsing_pqc_pkesk() {
    pretty_env_logger::try_init().ok();

    // This is a message that is encrypted to one traditional PKESK and one PQC PKESK
    let (message, _) = Message::from_armor_file("./tests/message_pqc.asc").expect("ok");

    let Message::Encrypted { esk, .. } = message else {
        panic!("destructure encrypted message")
    };

    assert_eq!(esk.len(), 2);
}
