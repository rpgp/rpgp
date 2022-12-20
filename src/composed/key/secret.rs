use chrono::{self, SubsecRound};
use smallvec::SmallVec;

use crate::composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey};
use crate::crypto::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    self, KeyFlags, SignatureConfigBuilder, SignatureType, Subpacket, SubpacketData,
};
use crate::types::{KeyId, KeyTrait, SecretKeyTrait};

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

    pub fn sign<F>(self, key_pw: F) -> Result<SignedSecretKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&primary_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}

impl KeyTrait for SecretKey {
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
}

impl SecretSubkey {
    pub fn new(key: packet::SecretSubkey, keyflags: KeyFlags) -> Self {
        SecretSubkey { key, keyflags }
    }

    pub fn sign<F>(self, sec_key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedSecretSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            )),
            Subpacket::regular(SubpacketData::KeyFlags(self.keyflags.into())),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                Default::default(),
                SmallVec::from_slice(&sec_key.fingerprint()),
            )),
        ];

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(sec_key.algorithm())
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                sec_key.key_id(),
            ))])
            .build()?;
        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key)?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}

impl KeyTrait for SecretSubkey {
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}
