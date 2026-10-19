#![cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys-03")]

//! Tests for persistent symmetric key support

use std::{fs::File, io::BufReader, path::Path};

use pgp::{
    armor,
    composed::{
        Deserializable, DetachedSignature, Esk, Message, PublicOrSecret, TheRing,
        TransferablePersistentSymmetricKey,
    },
    packet::{Packet, PacketParser, PersistentSymmetricKey},
    types::{DecryptionKey, EskType, KeyDetails, Password, PlainSecretParams},
};

const PLAIN: &str = "Hello World";

fn get_psk() -> PersistentSymmetricKey {
    let key = File::open(Path::new("tests/persistent-symmetric/openpgp-js/key")).unwrap();
    let dearmor = armor::Dearmor::new(BufReader::new(key));
    let mut pp = PacketParser::new(BufReader::new(dearmor));
    let packet = pp.next().unwrap().unwrap();

    let Packet::PersistentSymmetricKey(psk) = packet else {
        unimplemented!()
    };

    eprintln!("fp: {:02x?}", psk.fingerprint());

    psk
}

#[test]
fn psk_openpgp_js_seipdv1() {
    let psk = get_psk();

    let seipdv1 = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/seipdv1.msg",
    ))
    .unwrap();
    let (msg, _) = Message::from_armor(BufReader::new(seipdv1)).unwrap();

    let mut ring = TheRing::default();

    if let Message::Encrypted { esk, .. } = &msg {
        assert_eq!(esk.len(), 1);

        let Esk::PublicKeyEncryptedSessionKey(pkesk) = &esk[0] else {
            unimplemented!()
        };

        let sk = psk
            .decrypt(&Password::empty(), pkesk.values().unwrap(), EskType::V3_4)
            .unwrap()
            .unwrap();

        ring.session_keys.push(sk);
    }

    let (mut msg, _res) = msg.decrypt_the_ring(ring, false).unwrap();

    eprintln!("{:?}", msg);

    let data = msg.as_data_string().unwrap();
    eprintln!("{:?}", data);

    assert_eq!(data, PLAIN);
}

#[test]
fn psk_openpgp_js_seipdv2() {
    let psk = get_psk();

    let seipdv2 = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/seipdv2.msg",
    ))
    .unwrap();
    let (msg, _) = Message::from_armor(BufReader::new(seipdv2)).unwrap();

    let mut ring = TheRing::default();

    if let Message::Encrypted { esk, .. } = &msg {
        assert_eq!(esk.len(), 1);

        let Esk::PublicKeyEncryptedSessionKey(pkesk) = &esk[0] else {
            unimplemented!()
        };

        let sk = psk
            .decrypt(&Password::empty(), pkesk.values().unwrap(), EskType::V6)
            .unwrap()
            .unwrap();

        ring.session_keys.push(sk);
    }

    let (mut msg, _res) = msg.decrypt_the_ring(ring, false).unwrap();

    eprintln!("{:?}", msg);

    let data = msg.as_data_string().unwrap();
    eprintln!("{:?}", data);

    assert_eq!(data, PLAIN);
}

#[test]
fn psk_openpgp_js_signature() {
    let tpsk: TransferablePersistentSymmetricKey = get_psk().into();

    let signed = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/detached.sig",
    ))
    .unwrap();
    let (detached, _) = DetachedSignature::from_armor_single(BufReader::new(signed)).unwrap();

    let pw = Password::empty();
    let verifier = tpsk.into_verifier(pw);

    detached
        .verify(&verifier, PLAIN.as_bytes())
        .expect("Verify failed");
}

#[test]
fn psk_openpgp_js_unlock() {
    const LOCKED: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

6HcGarKqJwAAAAAhCRoGyHyB8qS38ocJKANzxr0cbqMkI1l0UmpJykZn4kPx/RoJ
AwsDCBz8DhY8OyUt4Pr12GfCYGPJwfS0es1bF1gDrLzumG/ahoY1ol7n4aQytd49
JFUTK5ePmrY/XBD+8qyIHLME+TTyZw83DA==
-----END PGP PRIVATE KEY BLOCK-----";

    let (mut iter, _) =
        PublicOrSecret::from_armor_many(BufReader::new(LOCKED.as_bytes())).expect("parse");

    let PublicOrSecret::PersistentSymmetric(tpsk) = iter.next().expect("next").expect("parsed")
    else {
        unreachable!("expected PSK")
    };

    let pw = Password::from("password");

    tpsk.key()
        .unlock(&pw, |_public, plain_secret| {
            assert!(matches!(plain_secret, PlainSecretParams::AEAD(_)));
            Ok(())
        })
        .expect("unlock")
        .expect("work")
}
