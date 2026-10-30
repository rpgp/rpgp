use pgp::{
    composed::{Deserializable, DetachedSignature, Message, SignedSecretKey},
    packet::{
        LiteralData, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
    },
    ser::Serialize,
    types::{KeyDetails, PacketHeaderVersion, Password, Tag, Timestamp},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
fn sig_odd() {
    let _ = pretty_env_logger::try_init();

    // signature contains an invalid issuerfingerprint packet
    let original_sig = std::fs::read_to_string("tests/sig_odd.asc").unwrap();

    let res = DetachedSignature::from_armor_single(original_sig.as_bytes());

    let Err(e) = res else {
        panic!("Signature should not be parsed.");
    };

    assert!(e.to_string().contains("Inconsistent subpacket length"));
}

#[test]
fn sig_type_confusion_message() {
    // test for https://github.com/rpgp/rpgp/security/advisories/GHSA-h834-358q-rx97

    let _ = pretty_env_logger::try_init();
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let (ssk, _headers) =
        SignedSecretKey::from_armor_file("./tests/autocrypt/bob@autocrypt.example.sec.asc")
            .expect("ssk");

    let bob_primary = &ssk.primary_key;

    let alice_uid = UserId::from_str(PacketHeaderVersion::New, "<alice@example.org>").unwrap();

    let mut config =
        SignatureConfig::from_key(&mut rng, bob_primary, SignatureType::CertGeneric).unwrap();

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(bob_primary.fingerprint())).unwrap(),
    ];

    // Make a normal certification signature packet
    let sig = config
        .clone()
        .sign_certification_third_party(
            bob_primary,
            &Password::empty(),
            bob_primary.public_key(),
            Tag::UserId,
            &alice_uid,
        )
        .unwrap();

    // Construct the `signed` data that was hashed into the signature
    let mut signed = Vec::new();

    //  hash bob public
    {
        let mut bob = Vec::new();
        bob_primary.public_key().to_writer(&mut bob).unwrap();

        signed.push(0x99);
        signed.extend(&(bob.len() as u16).to_be_bytes());
        signed.extend(&bob);
    }

    // hash user id
    {
        let mut uid = Vec::new();
        alice_uid.to_writer(&mut uid).unwrap();

        signed.push(0xb4);
        signed.extend(&(uid.len() as u32).to_be_bytes());
        signed.extend(&uid);
    }

    // Make a literal data packet from the signed data, and use it as part of a prefixed-signed message
    let lit = LiteralData::from_bytes(&[][..], signed.into()).unwrap();

    let mut msg = Vec::new();
    sig.to_writer_with_header(&mut msg).unwrap();
    lit.to_writer_with_header(&mut msg).unwrap();

    // Parse the constructed message and verify its signature
    let mut msg = Message::from_bytes(msg.as_ref()).expect("message");
    let _ = msg.as_data_vec();

    let res = msg.verify(&bob_primary.public_key());

    // Signature must be rejected based on its type, even though it is cryptographically valid
    assert!(res.is_err(), "signature must be rejected")
}
