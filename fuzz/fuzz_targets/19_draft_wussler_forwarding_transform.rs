#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::{Deserializable, Esk, Message, SignedSecretKey},
    packet::PublicKeyEncryptedSessionKey,
};

// /// key and proxy parameter examples copied from tests/forwarding.rs
// const ENCRYPTED_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

// wV4DFVflUJOTBRASAQdAdvFLPtXcvwSkEwbwmnjOrL6eZLh5ysnVpbPlgZbZwjgw
// yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
// 0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
// 7lM8r1DumNnO8srssko2qIja
// =uOPV
// -----END PGP MESSAGE-----";

// const FORWARDEE_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

// xVgEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faBvsf9
// R2c5ZzYAAP9bFL4nPBdo04ei0C2IAh5RXOpmuejGC3GAIn/UmL5cYQ+XzRtjaGFy
// bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CigQTFggAPAUCZAdtGAmQFXJtmBzDhdcW
// IQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbAwIeAQIZAQILBwIVCAIWAAIiAQAAJKYA
// /2qY16Ozyo5erNz51UrKViEoWbEpwY3XaFVNzrw+b54YAQC7zXkf/t5ieylvjmA/
// LJz3/qgH5GxZRYAH9NTpWyW1AsdxBGQHbRgSCisGAQQBl1UBBQEBB0CxmxoJsHTW
// TiETWh47ot+kwNA1hCk1IYB9WwKxkXYyIBf/CgmKXzV1ODP/mRmtiBYVV+VQk5MF
// EAAA/1NW8D8nMc2ky140sPhQrwkeR7rVLKP2fe5n4BEtAnVQEB3CeAQYFggAKgUC
// ZAdtGAmQFXJtmBzDhdcWIQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbUAAAl/8A/iIS
// zWBsBR8VnoOVfEE+VQk6YAi7cTSjcMjfsIez9FYtAQDKo9aCMhUohYyqvhZjn8aS
// 3t9mIZPc+zRJtCHzQYmhDg==
// =lESj
// -----END PGP PRIVATE KEY BLOCK-----";

// const PROXY_PARAMETER_K: [u8; 32] = [
//     0x04, 0xb6, 0x57, 0x04, 0x5f, 0xc9, 0xc0, 0x75, 0x9c, 0x5f, 0xd1, 0x1d, 0x8c, 0xa7, 0x5a, 0x2b,
//     0x1a, 0xa1, 0x01, 0xc9, 0xc8, 0x96, 0x49, 0x0b, 0xce, 0xc1, 0x00, 0xf9, 0x41, 0xe9, 0x7e, 0x0e,
// ];

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    proxy_parameter: [u8; 32],
    pkesk_message: String,
    forwardee_key: String,
}

fuzz_target!(|data: Input| {
    let message_res = Message::from_string(&data.pkesk_message);
    // let message_res = Message::from_string(ENCRYPTED_MESSAGE);

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok((message, _)) => {
            let Message::Encrypted { ref esk, .. } = &message else {
                return;
            };

            let mut esk_pkesk_list: Vec<PublicKeyEncryptedSessionKey> = vec![];

            for item in esk {
                match item {
                    // we're only interested in this type
                    Esk::PublicKeyEncryptedSessionKey(k) => {
                        esk_pkesk_list.push(k.clone());
                    }
                    Esk::SymKeyEncryptedSessionKey(_k) => {
                        // do nothing
                    }
                }
            }

            // we need at least one PKESK
            if esk_pkesk_list.len() < 1 {
                return;
            }

            // item availability checked above
            let first_esk_pkesk = &esk_pkesk_list[0];

            let key1_res = SignedSecretKey::from_string(&data.forwardee_key);
            // let key1_res = SignedSecretKey::from_string(FORWARDEE_KEY);

            match key1_res {
                Err(_) => return,
                Ok((key1, _)) => {
                    if key1.secret_subkeys.len() < 1 {
                        return;
                    }

                    let forwardee_key = &key1.secret_subkeys[0].key;

                    let transform_result = first_esk_pkesk
                        .forwarding_transform(forwardee_key, data.proxy_parameter.into());
                    // .forwarding_transform(forwardee_key, PROXY_PARAMETER_K.into());

                    match transform_result {
                        Err(err) => {
                            #[cfg(feature = "fuzzer_verbose1")]
                            println!("fuzzer: error {}", err);
                        }
                        Ok(pkesk) => {
                            #[cfg(feature = "fuzzer_verbose1")]
                            println!("fuzzer: successful transform result: {:?}", pkesk);

                            // if we need a stronger signal for success
                            // panic!("fuzzer: artificial panic on success");
                        }
                    }
                }
            }
        }
    }
});
