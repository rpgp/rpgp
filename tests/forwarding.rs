//! Tests from https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-end-to-end-tests

#[test]
#[cfg(feature = "draft-wussler-openpgp-forwarding")]
fn test_forwarding_v4() {
    use pgp::{
        composed::{Deserializable, Message, SignedSecretKey},
        types::{EcdhPublicParams, Password, PublicKeyTrait, PublicParams},
    };

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

    const _ENCYPTED_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

wV4DFVflUJOTBRASAQdAdvFLPtXcvwSkEwbwmnjOrL6eZLh5ysnVpbPlgZbZwjgw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=uOPV
-----END PGP MESSAGE-----";

    const _PROXY_PARAMETER_K: &[u8] = &[
        0x04, 0xb6, 0x57, 0x04, 0x5f, 0xc9, 0xc0, 0x75, 0x9c, 0x5f, 0xd1, 0x1d, 0x8c, 0xa7, 0x5a,
        0x2b, 0x1a, 0xa1, 0x01, 0xc9, 0xc8, 0x96, 0x49, 0x0b, 0xce, 0xc1, 0x00, 0xf9, 0x41, 0xe9,
        0x7e, 0x0e,
    ];

    const PLAINTEXT: &str = "Message for Bob";

    const TRANSFORMED_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

wV4DB27Wn97eACkSAQdA62TlMU2QoGmf5iBLnIm4dlFRkLIg+6MbaatghwxK+Ccw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=pVRa
-----END PGP MESSAGE-----";

    let _ = pretty_env_logger::try_init();

    let (_recipient, _) = SignedSecretKey::from_string(RECIPIENT_KEY).expect("RECIPIENT_KEY");

    let (forwardee, _) = SignedSecretKey::from_string(FORWARDEE_KEY).expect("FORWARDEE_KEY");

    {
        // inspect the internal shape of the forwardee secret key:

        // 1. it has the replacement fingerprint parameter in its encryption subkey
        let PublicParams::ECDH(EcdhPublicParams::Curve25519 {
            replacement_fingerprint,
            ..
        }) = forwardee.secret_subkeys[0].key.public_key().public_params()
        else {
            panic!("expect ecdh")
        };

        const REPLACEMENT_FP: &str = "8a5f35753833ff9919ad88161557e55093930510";

        assert_eq!(
            replacement_fingerprint.unwrap().as_slice(),
            hex::decode(REPLACEMENT_FP).unwrap()
        );

        // 2. it has key flags "0x40" and "0x10" set on the encryption subkey binding
        let key_flags = forwardee.secret_subkeys[0].signatures[0].key_flags();
        assert!(key_flags.decrypt_forwarded());
        assert!(key_flags.shared());
    }

    // Forwardee decrypts the transformed message
    let (msg, _) = Message::from_string(TRANSFORMED_MESSAGE).unwrap();

    let mut msg = msg
        .decrypt(&Password::empty(), &forwardee)
        .expect("decrypt");

    let plain = msg.as_data_vec().unwrap();

    assert_eq!(plain, PLAINTEXT.as_bytes());

    // TODO: implement transformation?
}
