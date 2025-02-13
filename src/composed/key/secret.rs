use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::Rng;

use crate::composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey};
use crate::errors::Result;
use crate::packet::{self, KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use crate::ser::Serialize;
use crate::types::{KeyVersion, SecretKeyTrait};

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

    pub fn sign<R, F>(self, mut rng: R, key_pw: F) -> Result<SignedSecretKey>
    where
        R: CryptoRng + Rng,
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&mut rng, &primary_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, &primary_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, &primary_key, key_pw.clone()))
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

    pub fn sign<R, F, K>(self, mut rng: R, sec_key: &K, key_pw: F) -> Result<SignedSecretSubKey>
    where
        R: CryptoRng + Rng,
        F: (FnOnce() -> String) + Clone,
        K: SecretKeyTrait + Serialize,
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
            Subpacket::regular(SubpacketData::KeyFlags(self.keyflags.into()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(sec_key.fingerprint()))?,
        ];
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::Issuer(sec_key.key_id()))?];

        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key.public_key())?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}
