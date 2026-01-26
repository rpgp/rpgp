//! Tests for persistent symmetric key support

use std::{fs::File, io::BufReader, path::Path};

use pgp::{
    composed::{Esk, Message, TheRing},
    packet::{Packet, PacketParser, PersistentSymmetricKey},
    types::{DecryptionKey, EskType, Password},
};

fn get_psk() -> PersistentSymmetricKey {
    let key = File::open(Path::new("tests/persistent-symmetric/openpgp-js/key.bin")).unwrap();
    let mut pp = PacketParser::new(BufReader::new(key));
    let packet = pp.next().unwrap().unwrap();

    let Packet::PersistentSymmetricKey(psk) = packet else {
        unimplemented!()
    };

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

    let (msg, _res) = msg.decrypt_the_ring(ring, false).unwrap();

    eprintln!("{:?}", msg);
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

    let (msg, _res) = msg.decrypt_the_ring(ring, false).unwrap();

    eprintln!("{:?}", msg);
}

#[test]
fn psk_openpgp_js_seipdv2_mixed() {
    // A message in which the SEIPD container uses a different symmetric algorithm than the
    // persistent symmetric key and pkesk encryption.

    let psk = get_psk();

    let seipdv2 = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/seipdv2-mixed-algo.msg",
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

    let (msg, _res) = msg.decrypt_the_ring(ring, false).unwrap();

    eprintln!("{:?}", msg);
}

#[test]
fn psk_openpgp_js_signed() {
    let psk = get_psk();

    let signed = File::open(Path::new(
        "tests/persistent-symmetric/openpgp-js/signed.msg",
    ))
    .unwrap();
    let (mut msg, _) = Message::from_armor(BufReader::new(signed)).unwrap();

    let pw = Password::empty();
    let unlocked = psk.as_unlockable(&pw);

    let _payload = msg.as_data_vec();

    let _sig = msg.verify(&unlocked).expect("failed to verify");
}
