use pgp::{
    armor,
    composed::{
        ArmorOptions, Deserializable, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
        SignedSecretSubKey,
    },
    packet::{SecretKey, SecretSubkey},
    types::{EncryptedSecretParams, LocatorHint, S2kParams, SecretParams},
};

pub fn main() {
    let (spk, _headers) = SignedPublicKey::from_armor_single(std::io::stdin()).unwrap();

    const NAME: &str = "Old OpenPGP card";

    let SignedPublicKey {
        primary_key,
        details,
        public_subkeys,
    } = spk;

    let primary_secret = SecretKey::new(
        primary_key,
        SecretParams::Encrypted(EncryptedSecretParams::new(
            Vec::new().into(),
            S2kParams::External(LocatorHint::BestEffort {
                name: Some(NAME.to_string()),
            }),
        )),
    )
    .expect("FIXME");

    let secret_subkeys: Vec<SignedSecretSubKey> = public_subkeys
        .into_iter()
        .map(|SignedPublicSubKey { key, signatures }| {
            let secret = SecretSubkey::new(
                key,
                SecretParams::Encrypted(EncryptedSecretParams::new(
                    Vec::new().into(),
                    S2kParams::External(LocatorHint::BestEffort {
                        name: Some(NAME.to_string()),
                    }),
                )),
            )
            .expect("FIXME");

            SignedSecretSubKey {
                key: secret,
                signatures,
            }
        })
        .collect();

    let ssk = SignedSecretKey {
        primary_key: primary_secret,
        details,
        secret_subkeys,
        public_subkeys: Vec::new(),
    };

    armor::write(
        &ssk,
        armor::BlockType::PrivateKey,
        &mut std::io::stdout(),
        ArmorOptions::default().headers,
        false,
    )
    .expect("write to armor");
}
