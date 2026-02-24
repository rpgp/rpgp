#![cfg(feature = "draft-wussler-openpgp-forwarding")]

//! End-to-end tests for draft-wussler-openpgp-forwarding functionality
//!
//! See <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-end-to-end-tests>

use std::io::BufReader;

use pgp::{
    armor::{BlockType, Dearmor},
    composed::{
        ArmorOptions, Deserializable, EncryptionCaps, Esk, KeyType, Message, MessageBuilder,
        SecretKeyParamsBuilder, SignedSecretKey, SignedSecretSubKey, SubkeyParamsBuilder,
    },
    crypto::{ecc_curve::ECCCurve, sym::SymmetricKeyAlgorithm},
    packet,
    packet::{KeyFlags, Packet, PacketParser, PubKeyInner},
    types::{
        EcdhKdfType, EcdhPublicParams, Fingerprint, KeyDetails, KeyVersion, Password, PublicParams,
        Timestamp,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const RECIPIENT_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAGzrOpvCFCxQ6hmpP52fBtbYmqkPM+TF9oBei
x9QWcnEAAQDa54PERHLvDqIMo0f03+mJXMTR3Dwq+qi5LTaflQFDGxEdzRNib2Ig
PGJvYkBwcm90b24ubWU+wooEExYIADwFAmQHbRgJkCLL+xMJ+Hy4FiEEm77zV6Zb
syLVIzOyIsv7Ewn4fLgCGwMCHgECGQECCwcCFQgCFgACIgEAAAnFAPwPoXgScgPr
KQFzu1ltPuHodEaDTtb+/wRQ1oAbuSdDgQD7B82NJgyEZInC/4Bwuc+ysFgaxW2W
gtypuW5vZm44FAzHXQRkB20YEgorBgEEAZdVAQUBAQdAeUTOhlO2RBUGH6B7127u
a82Mmjv62/GKZMpbNFJgqAcDAQoJAAD/Sd14Xkjfy1l8r0vQ5Rm+jBG4EXh2G8XC
PZgMz5RLa6gQ4MJ4BBgWCAAqBQJkB20YCZAiy/sTCfh8uBYhBJu+81emW7Mi1SMz
siLL+xMJ+Hy4AhsMAAAKagEA4Knj6S6nG24nuXfqkkytPlFTHwzurjv3+qqXwWL6
3RgA/Rvy/NcpCizSOL3tLLznwSag7/m6JVy9g6unU2mZ5QoI
=un5O
-----END PGP PRIVATE KEY BLOCK-----";

const FORWARDEE_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faBvsf9
R2c5ZzYAAP9bFL4nPBdo04ei0C2IAh5RXOpmuejGC3GAIn/UmL5cYQ+XzRtjaGFy
bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CigQTFggAPAUCZAdtGAmQFXJtmBzDhdcW
IQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbAwIeAQIZAQILBwIVCAIWAAIiAQAAJKYA
/2qY16Ozyo5erNz51UrKViEoWbEpwY3XaFVNzrw+b54YAQC7zXkf/t5ieylvjmA/
LJz3/qgH5GxZRYAH9NTpWyW1AsdxBGQHbRgSCisGAQQBl1UBBQEBB0CxmxoJsHTW
TiETWh47ot+kwNA1hCk1IYB9WwKxkXYyIBf/CgmKXzV1ODP/mRmtiBYVV+VQk5MF
EAAA/1NW8D8nMc2ky140sPhQrwkeR7rVLKP2fe5n4BEtAnVQEB3CeAQYFggAKgUC
ZAdtGAmQFXJtmBzDhdcWIQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbUAAAl/8A/iIS
zWBsBR8VnoOVfEE+VQk6YAi7cTSjcMjfsIez9FYtAQDKo9aCMhUohYyqvhZjn8aS
3t9mIZPc+zRJtCHzQYmhDg==
=lESj
-----END PGP PRIVATE KEY BLOCK-----";

const ENCRYPTED_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

wV4DFVflUJOTBRASAQdAdvFLPtXcvwSkEwbwmnjOrL6eZLh5ysnVpbPlgZbZwjgw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=uOPV
-----END PGP MESSAGE-----";

const PROXY_PARAMETER_K: &[u8] = &[
    0x04, 0xb6, 0x57, 0x04, 0x5f, 0xc9, 0xc0, 0x75, 0x9c, 0x5f, 0xd1, 0x1d, 0x8c, 0xa7, 0x5a, 0x2b,
    0x1a, 0xa1, 0x01, 0xc9, 0xc8, 0x96, 0x49, 0x0b, 0xce, 0xc1, 0x00, 0xf9, 0x41, 0xe9, 0x7e, 0x0e,
];

const PLAINTEXT: &str = "Message for Bob";

const TRANSFORMED_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

wV4DB27Wn97eACkSAQdA62TlMU2QoGmf5iBLnIm4dlFRkLIg+6MbaatghwxK+Ccw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=pVRa
-----END PGP MESSAGE-----";

#[test]
fn forward_a_3_calculate_proxy_param() {
    // Calculate proxy parameter (test vectors from a.3 end-to-end test)
    //
    // <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-end-to-end-tests>

    let _ = pretty_env_logger::try_init();

    let (recipient, _) = SignedSecretKey::from_string(RECIPIENT_KEY).expect("RECIPIENT_KEY");

    let recipient_key = &recipient.secret_subkeys[0].key;

    let (forwardee, _) = SignedSecretKey::from_string(FORWARDEE_KEY).expect("FORWARDEE_KEY");
    let forwardee_key = &forwardee.secret_subkeys[0].key;

    let k = recipient_key
        .generate_proxy_parameter(forwardee_key)
        .expect("generate_proxy_parameter");

    assert_eq!(
        &k[..],
        hex::decode("04b657045fc9c0759c5fd11d8ca75a2b1aa101c9c896490bcec100f941e97e0e").unwrap()
    );
}

#[test]
fn forward_a_3_transform_pkesk() {
    let _ = pretty_env_logger::try_init();

    // Get the PKESK from ENCYPTED_MESSAGE
    let (msg, _) = Message::from_string(ENCRYPTED_MESSAGE).unwrap();
    let Message::Encrypted { esk, .. } = msg else {
        unimplemented!()
    };
    assert_eq!(esk.len(), 1);
    let Esk::PublicKeyEncryptedSessionKey(pkesk) = &esk[0] else {
        unimplemented!();
    };

    // Calculate the transformed Pkesk for FORWARDEE_KEY
    let (forwardee, _) = SignedSecretKey::from_string(FORWARDEE_KEY).expect("FORWARDEE_KEY");

    eprintln!(
        "forwardee fp {:#02x?}",
        &forwardee.secret_subkeys[0].key.fingerprint()
    );
    eprintln!("forwardee {:#02x?}", &forwardee.secret_subkeys[0].key,);

    let transformed_pkesk = pkesk
        .forwarding_transform(
            &forwardee.secret_subkeys[0].key,
            PROXY_PARAMETER_K.try_into().unwrap(),
        )
        .expect("transform");

    // Compare `transformed_pkesk` with the expected output
    let (msg, _) = Message::from_string(TRANSFORMED_MESSAGE).unwrap();
    let Message::Encrypted { esk, .. } = msg else {
        unimplemented!()
    };
    let Esk::PublicKeyEncryptedSessionKey(expected_pkesk) = &esk[0] else {
        unimplemented!();
    };

    assert_eq!(&transformed_pkesk, expected_pkesk);
}

#[test]
fn forward_a_3_decrypt_forwarded() {
    // Perform end-to-end decryption tests on the test vectors from draft-wussler-openpgp-forwarding A.3
    //
    // See <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-end-to-end-tests>

    let _ = pretty_env_logger::try_init();

    let (_recipient, _) = SignedSecretKey::from_string(RECIPIENT_KEY).expect("RECIPIENT_KEY");

    let (forwardee, _) = SignedSecretKey::from_string(FORWARDEE_KEY).expect("FORWARDEE_KEY");

    {
        // inspect the internal shape of the forwardee secret key:

        // 1. it has the replacement fingerprint parameter in its encryption subkey
        let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { ecdh_kdf_type, .. }) =
            forwardee.secret_subkeys[0].key.public_key().public_params()
        else {
            panic!("expect ecdh")
        };

        let EcdhKdfType::Replaced {
            replacement_fingerprint,
        } = ecdh_kdf_type
        else {
            panic!("expect ecdh")
        };

        const REPLACEMENT_FP: &str = "8a5f35753833ff9919ad88161557e55093930510";

        assert_eq!(
            replacement_fingerprint.as_slice(),
            hex::decode(REPLACEMENT_FP).unwrap()
        );

        // 2. it has key flags "0x40" and "0x10" set on the encryption subkey binding
        let key_flags = forwardee.secret_subkeys[0].signatures[0].key_flags();
        assert!(key_flags.draft_decrypt_forwarded());
        assert!(key_flags.shared());
    }

    // Forwardee decrypts the transformed message
    let (msg, _) = Message::from_string(TRANSFORMED_MESSAGE).unwrap();

    let mut msg = msg
        .decrypt(&Password::empty(), &forwardee)
        .expect("decrypt");

    let plain = msg.as_data_vec().unwrap();

    assert_eq!(plain, PLAINTEXT.as_bytes());
}

#[test]
fn forward_end_to_end() {
    // A full end-to-end test for all functionality in draft-wussler-openpgp-forwarding
    // which produces all artifacts from scratch with rPGP:
    //
    // - generate recipient, forwardee keys
    // - calculate proxy parameter
    // - encrypt a message to recipient
    // - transform message for forwardee
    // - decrypt message as forwardee

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    // # Generate keys for recipient and forwarder

    // ## Robert, the recipient
    let robert_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .primary_user_id("robert".into())
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let robert = robert_params.generate(&mut rng).unwrap();
    let robert_pub = robert.to_public_key();

    // ## Frederick, the forwardee
    let frederick_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .primary_user_id("frederick".into())
        .build()
        .unwrap();

    let mut frederick = frederick_params.generate(&mut rng).unwrap();

    let (mut public_params, secret_params) = KeyType::ECDH(ECCCurve::Curve25519)
        .generate(&mut rng)
        .unwrap();
    let mut keyflags = KeyFlags::default();
    keyflags.set_encrypt_comms(true);
    keyflags.set_encrypt_storage(true);
    keyflags.set_shared(true);
    keyflags.set_draft_decrypt_forwarded(true);

    let PublicParams::ECDH(EcdhPublicParams::Curve25519 {
        ref mut ecdh_kdf_type,
        ..
    }) = public_params
    else {
        unimplemented!()
    };

    let Fingerprint::V4(robert_fp) = robert.secret_subkeys[0].fingerprint() else {
        unimplemented!()
    };

    *ecdh_kdf_type = EcdhKdfType::Replaced {
        replacement_fingerprint: robert_fp,
    };

    let pub_key = PubKeyInner::new(
        KeyVersion::V4,
        KeyType::ECDH(ECCCurve::Curve25519).to_alg(),
        Timestamp::now(),
        None,
        public_params,
    )
    .unwrap();
    let pub_sub = packet::PublicSubkey::from_inner(pub_key).unwrap();

    let subkey_binding = pub_sub
        .sign(
            &mut rng,
            &frederick.primary_key,
            frederick.public_key(),
            &Password::empty(),
            keyflags,
            None,
        )
        .unwrap();

    let sec_sub = packet::SecretSubkey::new(pub_sub, secret_params).unwrap();

    frederick
        .secret_subkeys
        .push(SignedSecretSubKey::new(sec_sub, vec![subkey_binding]));

    // # Calculate proxy parameter (test vectors from a.3 end-to-end test)

    // TODO: ForwardingInstance type?
    let proxy_parameter = robert.secret_subkeys[0]
        .key
        .generate_proxy_parameter(&frederick.secret_subkeys[0].key)
        .expect("generate_proxy_parameter");

    // # Produce an encrypted message for robert
    const MESSAGE_FOR_ROBERT: &str = "hello robert";

    let builder = MessageBuilder::from_bytes(&[][..], MESSAGE_FOR_ROBERT.as_bytes().to_vec());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
    builder
        .encrypt_to_key(&mut rng, &robert_pub.public_subkeys[0].key)
        .unwrap();

    let encrypted = builder
        .to_armored_string(&mut rng, ArmorOptions::default())
        .unwrap();

    eprintln!("{}", encrypted);

    let mut pp = PacketParser::new(BufReader::new(Dearmor::new(encrypted.as_bytes())));
    let pkesk = pp.next().unwrap().unwrap();
    let seipd = pp.next().unwrap().unwrap();

    let Packet::PublicKeyEncryptedSessionKey(ref pkesk) = pkesk else {
        unimplemented!();
    };

    // # Calculate the transformed Message for frederick
    let transformed_pkesk = pkesk
        .forwarding_transform(&frederick.secret_subkeys[0].key, proxy_parameter)
        .expect("transform");

    let transformed_msg = vec![
        Packet::PublicKeyEncryptedSessionKey(transformed_pkesk),
        seipd,
    ];

    let mut armored = Vec::new();
    pgp::armor::write(
        &transformed_msg,
        BlockType::Message,
        &mut armored,
        None,
        true,
    )
    .unwrap();

    let armored = String::from_utf8_lossy(&armored);

    eprintln!("transformed message for frederick");
    eprintln!("{}", armored);

    // # Frederick decrypts the forwarded message

    let (msg, _) = Message::from_string(&armored).unwrap();

    let mut msg = msg
        .decrypt(&Password::empty(), &frederick)
        .expect("decrypt");

    let plain = msg.as_data_vec().unwrap();

    assert_eq!(plain, MESSAGE_FOR_ROBERT.as_bytes());
}
