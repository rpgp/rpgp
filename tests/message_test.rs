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
use std::io::{Cursor, Read};

use pgp::composed::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
use pgp::types::KeyTrait;

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

fn test_parse_msg(entry: &str, base_path: &str, is_normalized: bool) {
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
    decrypt_key.verify().expect("invalid decryption key");

    let decrypt_id = hex::encode(decrypt_key.key_id());

    info!("decrypt key (ID={})", &decrypt_id);
    if let Some(id) = &details.keyid {
        assert_eq!(id, &decrypt_id, "invalid keyid");
    }

    let verify_key = if let Some(verify_key_str) = details.verify_key.clone() {
        let mut verify_key_file = File::open(format!("{base_path}/{verify_key_str}")).unwrap();
        let (verify_key, _headers) = SignedPublicKey::from_armor_single(&mut verify_key_file)
            .expect("failed to read verification key");
        verify_key.verify().expect("invalid verification key");

        let verify_id = hex::encode(verify_key.key_id());
        info!("verify key (ID={})", &verify_id);
        Some(verify_key)
    } else {
        None
    };

    let file_name = entry.replace(".json", ".asc");
    let cipher_file_path = format!("{base_path}/{file_name}");
    let mut cipher_file = File::open(&cipher_file_path).unwrap();

    let (message, headers) =
        Message::from_armor_single(&mut cipher_file).expect("failed to parse message");
    info!("message: {:?}", &message);

    match &message {
        Message::Encrypted { .. } => {
            let (mut decrypter, ids) = message
                .decrypt(|| details.passphrase.clone(), &[&decrypt_key])
                .expect("failed to init decryption");
            assert_eq!(ids.len(), 1);

            let decrypted = decrypter
                .next()
                .expect("no message")
                .expect("message decryption failed");

            if let Some(verify_key) = verify_key {
                decrypted
                    .verify(&verify_key.primary_key)
                    .expect("message verification failed");
            }

            // serialize and check we get the same thing
            let serialized = decrypted.to_armored_bytes(None).unwrap();

            // and parse them again
            let (decrypted2, _headers) = Message::from_armor_single(Cursor::new(&serialized))
                .expect("failed to parse round2");
            assert_eq!(decrypted, decrypted2);

            let raw = match decrypted {
                Message::Literal(data) => data,
                Message::Compressed(data) => {
                    let m = Message::from_bytes(data.decompress().unwrap()).unwrap();

                    // serialize and check we get the same thing
                    let serialized = m.to_armored_bytes(None).unwrap();

                    // and parse them again
                    let (m2, _headers) = Message::from_armor_single(Cursor::new(&serialized))
                        .expect("failed to parse round3");
                    assert_eq!(m, m2);

                    m.get_literal().unwrap().clone()
                }
                _ => panic!("unexpected message type: {decrypted:?}"),
            };

            assert_eq!(
                ::std::str::from_utf8(raw.data()).unwrap(),
                details.textcontent.unwrap_or_default()
            );
        }
        Message::Signed { signature, .. } => {
            println!("signature: {signature:?}");
        }
        _ => {
            // TODO: some other checks?
            panic!("this test should not have anything else?");
        }
    }

    // serialize and check we get the same thing
    let serialized = message.to_armored_string(Some(&headers)).unwrap();

    if is_normalized {
        let mut cipher_file = File::open(&cipher_file_path).unwrap();
        let mut expected_bytes = String::new();
        cipher_file.read_to_string(&mut expected_bytes).unwrap();
        // normalize read in line endings to unix
        assert_eq!(serialized, expected_bytes.replace("\r\n", "\n"));
    }

    // and parse them again
    let (message2, headers2) =
        Message::from_armor_single(Cursor::new(&serialized)).expect("failed to parse round2");
    assert_eq!(headers, headers2);
    assert_eq!(message, message2);
}

macro_rules! msg_test {
    ($name:ident, $pos:expr, $normalized:expr) => {
        #[test]
        fn $name() {
            test_parse_msg(
                &format!("{}.json", $pos),
                "./tests/opengpg-interop/testcases/messages",
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
    let mut msg_file = File::open("./tests/partial.asc").unwrap();
    Message::from_armor_single(&mut msg_file).expect("failed to parse message");
}

#[test]
fn msg_regression_01() {
    let mut msg_file = File::open("./tests/regression-01.asc").unwrap();
    Message::from_armor_single(&mut msg_file).expect("failed to parse message");
}

#[test]
fn msg_large_indeterminate_len() {
    let _ = pretty_env_logger::try_init();

    let mut msg_file = File::open("./tests/indeterminate.asc").unwrap();
    let (message, _headers) =
        Message::from_armor_single(&mut msg_file).expect("failed to parse message");

    let mut key_file = File::open("./tests/openpgpjs/x25519.sec.asc").unwrap();
    let (decrypt_key, _headers) =
        SignedSecretKey::from_armor_single(&mut key_file).expect("failed to parse key");

    let decrypted = message
        .decrypt(|| "moon".to_string(), &[&decrypt_key])
        .expect("failed to decrypt message")
        .0
        .next()
        .expect("no mesage")
        .expect("message decryption failed");

    let raw = match decrypted {
        Message::Literal(data) => data,
        Message::Compressed(data) => {
            let m = Message::from_bytes(data.decompress().unwrap()).unwrap();

            m.get_literal().unwrap().clone()
        }
        _ => panic!("unexpected message type: {decrypted:?}"),
    };

    assert_eq!(
        ::std::str::from_utf8(raw.data()).unwrap(),
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
    let mut msg_file = File::open("./tests/literal-text-signed.asc").unwrap();
    let (msg, _) = Message::from_armor_single(&mut msg_file).expect("failed to parse message");

    msg.verify(&pkey).unwrap();
}
