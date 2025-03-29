#![no_main]

use std::io::Read;

use libfuzzer_sys::fuzz_target;
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use pgp::{
    composed::{Deserializable, Message},
    ArmorOptions, MessageBuilder, SignedSecretKey,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// build message and try decryption with a genuine private key
fuzz_target!(|data: &[u8]| {
    let message_res = Message::from_bytes(data);

    let data = data.to_vec();

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(_message) => {
            // file content of ./tests/openpgp-interop/testcases/messages/gnupg-v1-001-decrypt.asc
            // included here to avoid I/O operations
            let key_input = "-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQIGBFQPSZEDBACa+JwIqOqEtTYyaLrIoGghGUFjy87u0tkh9fO90ZJSiRHHseUV
3OiGVAnhYdu72KRojFbB59/PY52WI+MXWxvKhrHRKuTk+/mlt9VJP0aNp0T0rPxN
E60tgzmP/CDX3wLfgvO8Bfku3EGzxHhjigU3JlhqqsV+K2bAT5d1cWoMcQARAQAB
/gcDCMsY53iE8vBVYCJx9xivcNO9nWDCrtlGm2euydlp5MCZULhFBdUt4/jaB80G
/9oCSF5/5VOibbk5d0feuY7to031oS4rOCZMlsjisfD8v9kVfc38aN7c32DdmfJs
M5Cujqx0vwwYPnU99dZeCfXIskEsCgLeEeCi3daAa3jgQOJqGVTp3Nu7MQqBaa6N
ybbkQs9qbHHON+t+S0+119Q+m6Fh3E7/FgLoFWwNxanQWDpK4qximayeOI8NyOQT
3urrKB36ldcuOXuLn3vpAvfZALos0Y9fLuzMzkYgQ8ghweLkbH01r4GUykjLM7jb
kLEB0ihHuRDvwgy77MvkrgqoOReMRYDzgWTisiSVj8OQRhzZ4nHYiyPMKAqUuAhh
DNB/X9fA9FSkdf3S3JZMypuZdqsLf9+fqGSsJ0wXD6O0TXoAnoJpKHcp3Py+ps1h
+SFqw/2/PKoJShgRXCwbzEO+YTgqNAtTfFHas5BrY45ggTxGug+XMSC0D3JzYS1y
c2EtZGVmYXVsdIilBBMDAgAPBQJUkx+RAgsHAhUIAh4BAAoJEATHhwPvv5QWp8oD
/jDlPbR4AgpEwLqYOI5dUO0gQoG2G+2JK2qCNuy8SMTMBfiPz1TW62HnmOFz1wWR
gwNwIl4+F1qC4o8nxORIKyXJBngUhekSifWoWPyMzp2om7Ipta/dQjKUwZV2fVSt
iqqK1u7l1t0pYLs3Giy8V0PAflDKkVIZqw9xCJegK6RanQIGBFQPSZECBACROoHb
3Ayw3PzuW/gZYf/Hv3wEcXAwaUibDhPOp+zdj673txWte7AU9k9aTwzogd2JkL+q
RwtWnxR2+ap7BWP+Wkt5qfs7JjVtC9qA+L0mNEEZyiMwYd90Gb9g4uZCnxTSDhoD
KL5rMlyEmWHgMLJyw0kk27IB4xkfH6ncn+wWhwARAQAB/gcDCMsY53iE8vBVYHoS
jBkk3Dtxz27pYZnbYLVyQjSsT+O55w8fU/kx88txHbyuljhIKK/R66/ejErGOP6v
yKptsEnjglZjspyNWd4K4cxx9mkdo/2iNcrvH96pDprmWs1hQEqae8kUmx52daCS
ljT+VPrEv1iDgDoJ3QpQ5x56EQnb5w0LYYshOFpWeQuvuklRwIjvSAVcZ6sNm2lB
N+uwgjH/Gw+I3i7yoSHiQucfUpqrmczsDxQ0LrfdWeBKTFLjqgNzDiOAh8RSX3A6
0j7nAKZVqWwC3WInGs1YxdBmQ5nCioCaplOLlJmc2+HMGQmFqjoSxdul1RGCt0D8
QVsaU3n/zIbOnf1vLYTYWyALg/KbV4j40STSHA2zQm772X2BxAOP6wzERbXJ1MUt
o1Zt7aYRtU6MBc739H32XtxoGbyIGmAxUUBljUq+oMk5BoZo2YuCD4nk48ry+lrR
UrxgQ1AVisxye9dLSXekE4MCCGP1ysMjnCGInAQYAwIABgUCVA9JkQAKCRAEx4cD
77+UFiFKA/wOG2PxB1iDtDeLAUfOP0zMx6qBQfWCyWldKze/bom5SwbLT42+Aks9
B0RU6JKdd8WfwTlJyQeM56aUe1wPwVHBe+zTG+XvsYree3rQHFEgHTN3KEPHc6Ec
QqrhcYJ4IBFau0avBvi7QjsSOvePvIKFO/DuDIECRpLZjRW+VKisag==
=hU9G
-----END PGP PRIVATE KEY BLOCK-----";

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            // fixed seed PRNG for determinism
            let rng = ChaCha8Rng::seed_from_u64(0);

            // FUZZER OBSERVATION contrary to initial expectations, signing does not always succeed
            let mut builder = MessageBuilder::from_bytes("", data);
            builder = builder.sign(&*decrypt_key, Password::from("test"), HashAlgorithm::Sha256);
            let armored = builder
                .to_armored_string(rng, ArmorOptions::default())
                .unwrap();

            let signed_message_res = Message::from_armor(armored.as_bytes());
            match signed_message_res {
                Ok((mut signed_message, _)) => {
                    let mut sink = vec![];
                    let _ = signed_message.read_to_end(&mut sink);

                    let _verify_res = signed_message
                        .verify(&*decrypt_key.public_key())
                        .expect("we just signed this and expect it to verify");
                }
                // ignore
                Err(_e) => {}
            }
        }
    }
});
