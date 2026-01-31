//! Tests for persistent symmetric key support

use std::{fs::File, io::BufReader, path::Path};

use pgp::{
    armor,
    composed::{Deserializable, DetachedSignature, Esk, Message, TheRing},
    packet::{Packet, PacketParser, PersistentSymmetricKey},
    types::{DecryptionKey, EskType, KeyDetails, Password},
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
    let psk = get_psk();

    let signed = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/detached.sig",
    ))
    .unwrap();
    let (detached, _) = DetachedSignature::from_armor_single(BufReader::new(signed)).unwrap();

    let pw = Password::empty();
    let unlocked = psk.as_unlockable(&pw);

    detached
        .verify(&unlocked, PLAIN.as_bytes())
        .expect("Verify failed");
}
