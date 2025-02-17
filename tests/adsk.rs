use std::fs::File;

use pgp::types::{Fingerprint, PublicKeyTrait};
use pgp::SignedPublicKey;
use smallvec::SmallVec;

#[test]
fn load_adsk_pub() {
    // Handle a test certificate with key flags that span more than a single `u8`.
    // The test key was created with GnuPG, see https://www.gnupg.org/blog/20230321-adsk.html

    let _ = pretty_env_logger::try_init();

    let key_file = File::open("tests/adsk.pub.asc").unwrap();

    let (mut iter, _) = pgp::composed::signed_key::from_reader_many(key_file).expect("ok");

    let public: SignedPublicKey = match iter.next().expect("result") {
        Ok(pos) => {
            eprintln!("{:#?}", pos);
            pos.try_into().expect("public")
        }
        Err(e) => panic!("error: {:?}", e),
    };

    let adsk_subkey = public
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.fingerprint()
                == Fingerprint::V4(
                    hex::decode("7051E786F572CF85E023D8B9A59FE955A52FFD57")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
        })
        .unwrap();

    let sig = &adsk_subkey.signatures[0];

    let key_flags = sig.key_flags();
    eprintln!("key_flags {:?}", key_flags);

    let sv: SmallVec<_> = key_flags.into();
    eprintln!("key_flags SmallVec {:?}", sv);

    assert_eq!(sv.to_vec(), vec![0x0, 0x04]);
}
