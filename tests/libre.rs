//! Tests for non-OpenPGP formats from
//! https://www.ietf.org/archive/id/draft-koch-librepgp-03.html
//!
//! For some additional interoperability with GnuPG.

use std::io::BufReader;

use pgp::{
    composed::{Deserializable, Message, PlainSessionKey, SignedSecretKey},
    crypto::{hash::HashAlgorithm::Sha256, sym::SymmetricKeyAlgorithm},
    packet::{AeadProps, Packet, PacketParser},
    ser::Serialize,
    types::{Password, SkeskVersion, StringToKey},
};

/// Test vectors from
/// https://www.ietf.org/archive/id/draft-koch-librepgp-03.html#name-complete-ocb-encrypted-pack
const SKESK5: &str = "c3 3d 05 07 02 03 08 9f  0b 7d a3 e5 ea 64 77 90
  99 e3 26 e5 40 0a 90 93  6c ef b4 e8 eb a0 8c 67
  73 71 6d 1f 27 14 54 0a  38 fc ac 52 99 49 da c5
  29 d3 de 31 e1 5b 4a eb  72 9e 33 00 33 db ed";

const OCB: &str = "d4 49 01 07 02 0e 5e d2  bc 1e 47 0a be 8f 1d 64
  4c 7a 6c 8a 56 7b 0f 77  01 19 66 11 a1 54 ba 9c
  25 74 cd 05 62 84 a8 ef  68 03 5c 62 3d 93 cc 70
  8a 43 21 1b b6 ea f2 b2  7f 7c 18 d5 71 bc d8 3b
  20 ad d3 a0 8b 73 af 15  b9 a0 98";

fn decode(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>())
}

#[test]
fn libre_v5_skesk() {
    let skesk5 = decode(SKESK5).expect("hex");

    let mut pp = PacketParser::new(BufReader::new(&*skesk5));
    let p = match pp.next() {
        Some(Ok(p)) => p,
        Some(Err(e)) => panic!("could not parse skesk {:?}", e),
        None => panic!("no result"),
    };

    eprintln!("{:02x?}", p);

    let Packet::SymKeyEncryptedSessionKey(skesk) = &p else {
        panic!("expect skesk");
    };

    assert_eq!(skesk.version(), SkeskVersion::V5);

    let pgp::packet::SymKeyEncryptedSessionKey::V5 {
        packet_header: _,
        sym_algorithm,
        s2k,
        aead,
        encrypted_key,
    } = skesk
    else {
        panic!("expect v5 skesk");
    };

    assert_eq!(sym_algorithm, &SymmetricKeyAlgorithm::AES128);
    assert_eq!(
        s2k,
        &StringToKey::IteratedAndSalted {
            hash_alg: Sha256,
            count: 144,
            salt: [0x9f, 0x0b, 0x7d, 0xa3, 0xe5, 0xea, 0x64, 0x77]
        }
    );

    assert_eq!(
        aead,
        &AeadProps::Ocb {
            iv: [
                0x99, 0xe3, 0x26, 0xe5, 0x40, 0x0a, 0x90, 0x93, 0x6c, 0xef, 0xb4, 0xe8, 0xeb, 0xa0,
                0x8c
            ]
        }
    );

    assert_eq!(
        encrypted_key.as_ref(),
        &[
            0x67, 0x73, 0x71, 0x6d, 0x1f, 0x27, 0x14, 0x54, 0x0a, 0x38, 0xfc, 0xac, 0x52, 0x99,
            0x49, 0xda, // key
            0xc5, 0x29, 0xd3, 0xde, 0x31, 0xe1, 0x5b, 0x4a, 0xeb, 0x72, 0x9e, 0x33, 0x00, 0x33,
            0xdb, 0xed // tag
        ]
    );

    // -- roundtrip the skesk packet
    let mut out = vec![];
    let _ = p.to_writer(&mut out);

    assert_eq!(skesk5, out);

    // -- try decrypt
    let pw = Password::from("password");
    let sk = pgp::composed::decrypt_session_key_with_password(skesk, &pw).expect("decrypt");
    let PlainSessionKey::V5 { key } = &sk else {
        panic!("unexpected plain session key version");
    };

    // Decrypted CEK
    assert_eq!(
        *key,
        vec![
            0xd1, 0xf0, 0x1b, 0xa3, 0x0e, 0x13, 0x0a, 0xa7, 0xd2, 0x58, 0x2c, 0x16, 0xe0, 0x50,
            0xae, 0x44
        ]
    );
}

#[test]
fn libre_ocb_message() {
    const PLAIN: &str = "Hello, world!\n";

    let mut message = vec![];
    message.extend_from_slice(&decode(SKESK5).expect("hex"));
    message.extend_from_slice(&decode(OCB).expect("hex"));

    let msg = Message::from_bytes(BufReader::new(&*message)).expect("message from bytes");

    eprintln!("msg {:#?}", msg);

    let pw = Password::from("password");
    let mut dec = msg.decrypt_with_password(&pw).expect("decrypt");

    let plain = dec.as_data_vec().expect("data");

    assert_eq!(&plain, &PLAIN.as_bytes());
}

#[test]
/// Decrypt a very short OCB-encrypted message that was produced by GnuPG 2.4.7
///
/// This test data was produced by `gpg -e -a --force-ocb <plaintext-file>`
fn libre_ocb_msg_to_bob() {
    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/draft-bre-openpgp-samples-00/bob.sec.asc").unwrap(),
    )
    .unwrap();

    let (msg, _) = Message::from_armor_file("./tests/libre/msg_to_bob.asc").expect("msg");

    eprintln!("msg {:#?}", msg);

    let dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");
    let mut plain = dec.decompress().expect("decompress");

    eprintln!("dec {:#?}", plain);

    let decrypted = plain.as_data_string().unwrap();
    assert_eq!(&decrypted, "foo\n");
}

#[test]
/// Decrypt a slightly longer OCB-encrypted message, with a small chunk size,
/// that was produced by GnuPG 2.4.7
///
/// The plaintext is 300 bytes of /dev/random, the message was encrypted using
/// `gpg --force-ocb --chunk-size 6 -e -a <plaintext>`.
///
/// The OCB packet has a chunk size of 64 bytes.
fn libre_ocb_msg_to_bob_multi_chunk() {
    let (skey, _headers) = SignedSecretKey::from_armor_single(
        std::fs::File::open("./tests/draft-bre-openpgp-samples-00/bob.sec.asc").unwrap(),
    )
    .unwrap();

    let (msg, _) =
        Message::from_armor_file("./tests/libre/msg_to_bob_multi_chunk.asc").expect("msg");

    let dec = msg.decrypt(&Password::empty(), &skey).expect("decrypt");
    let mut plain = dec.decompress().expect("decompress");

    let decrypted = plain.as_data_vec().unwrap();
    assert_eq!(decrypted.len(), 300);
}
