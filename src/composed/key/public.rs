use chrono;

use composed::{KeyDetails, SignedPublicKey, SignedPublicSubKey};
use crypto::PublicKeyAlgorithm;
use errors::Result;
use packet::{self, KeyFlags, SignatureConfigBuilder, SignatureType, Subpacket};
use types::{KeyId, KeyTrait, SecretKeyTrait};

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    primary_key: packet::PublicKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicSubkey {
    key: packet::PublicSubkey,
    keyflags: KeyFlags,
}

impl PublicKey {
    pub fn new(
        primary_key: packet::PublicKey,
        details: KeyDetails,
        public_subkeys: Vec<PublicSubkey>,
    ) -> Self {
        PublicKey {
            primary_key,
            details,
            public_subkeys,
        }
    }

    pub fn sign<F>(self, sec_key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedPublicKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(sec_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(sec_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        })
    }
}

impl KeyTrait for PublicKey {
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> Option<KeyId> {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
}

impl PublicSubkey {
    pub fn new(key: packet::PublicSubkey, keyflags: KeyFlags) -> Self {
        PublicSubkey { key, keyflags }
    }

    pub fn sign<F>(self, sec_key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedPublicSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::SignatureCreationTime(chrono::Utc::now()),
            Subpacket::KeyFlags(self.keyflags.into()),
        ];

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(sec_key.algorithm())
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(vec![
                Subpacket::Issuer(sec_key.key_id().expect("missing key id")),
                Subpacket::IssuerFingerprint(sec_key.fingerprint()),
            ])
            .build()?;

        let signatures = vec![config.sign_key(sec_key, key_pw, &key)?];

        Ok(SignedPublicSubKey { key, signatures })
    }
}

impl KeyTrait for PublicSubkey {
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    fn key_id(&self) -> Option<KeyId> {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}
