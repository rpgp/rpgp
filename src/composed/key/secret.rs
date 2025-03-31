use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::Rng;

use crate::{
    composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey},
    errors::Result,
    packet::{self, KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::{KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
};

/// User facing interface to work with a secret key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
    secret_subkeys: Vec<SecretSubkey>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretSubkey {
    key: packet::SecretSubkey,
    keyflags: KeyFlags,
}

impl SecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: KeyDetails,
        public_subkeys: Vec<PublicSubkey>,
        secret_subkeys: Vec<SecretSubkey>,
    ) -> Self {
        SecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    pub fn sign<R>(self, mut rng: R, key_pw: &Password) -> Result<SignedSecretKey>
    where
        R: CryptoRng + Rng,
    {
        let primary_key = self.primary_key;
        let details =
            self.details
                .sign(&mut rng, &primary_key, primary_key.public_key(), key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, &primary_key, primary_key.public_key(), key_pw))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, &primary_key, primary_key.public_key(), key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}

impl SecretSubkey {
    pub fn new(key: packet::SecretSubkey, keyflags: KeyFlags) -> Self {
        SecretSubkey { key, keyflags }
    }

    pub fn sign<R, K, P>(
        self,
        mut rng: R,
        sec_key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedSecretSubKey>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let key = self.key;

        let mut config = match sec_key.version() {
            KeyVersion::V4 => SignatureConfig::v4(
                SignatureType::SubkeyBinding,
                sec_key.algorithm(),
                sec_key.hash_alg(),
            ),
            KeyVersion::V6 => SignatureConfig::v6(
                &mut rng,
                SignatureType::SubkeyBinding,
                sec_key.algorithm(),
                sec_key.hash_alg(),
            )?,
            v => unsupported_err!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
            Subpacket::regular(SubpacketData::KeyFlags(self.keyflags))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(sec_key.fingerprint()))?,
        ];
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::Issuer(sec_key.key_id()))?];

        let signatures =
            vec![config.sign_key_binding(sec_key, pub_key, key_pw, key.public_key())?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::composed::{Deserializable, SignedPublicKey};

    /// Based on the operations "split_public_key" in Deltachat
    #[test]
    fn test_split_key() {
        let (public, _) =
            SignedPublicKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.pub.asc")
                .unwrap();
        let (secret, _) =
            SignedSecretKey::from_armor_file("./tests/autocrypt/alice@autocrypt.example.sec.asc")
                .unwrap();

        secret.verify().unwrap();
        public.verify().unwrap();

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let unsigned_pubkey = secret.public_key();

        let signed_pubkey = unsigned_pubkey
            .sign(
                &mut rng,
                &secret.primary_key,
                secret.primary_key.public_key(),
                &Password::empty(),
            )
            .unwrap();

        assert_eq!(signed_pubkey.primary_key, public.primary_key);
    }
}
