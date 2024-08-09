use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::Rng;

use crate::composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey};
use crate::errors::Result;
use crate::packet::{
    self, KeyFlags, SignatureConfigBuilder, SignatureType, SignatureVersion, Subpacket,
    SubpacketData,
};
use crate::types::SecretKeyTrait;

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

    pub fn sign<R, F>(self, rng: &mut R, key_pw: F) -> Result<SignedSecretKey>
    where
        R: CryptoRng + Rng,
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(rng, &primary_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(rng, &primary_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(rng, &primary_key, key_pw.clone()))
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

    pub fn sign<R, F>(
        self,
        rng: &mut R,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<SignedSecretSubKey>
    where
        R: CryptoRng + Rng,
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            )),
            Subpacket::regular(SubpacketData::KeyFlags(self.keyflags.into())),
            Subpacket::regular(SubpacketData::IssuerFingerprint(sec_key.fingerprint())),
        ];

        let sig_version = sec_key.version().try_into()?;

        let config = match sig_version {
            SignatureVersion::V4 => SignatureConfigBuilder::v4()
                .typ(SignatureType::SubkeyBinding)
                .pub_alg(sec_key.algorithm())
                .hash_alg(sec_key.hash_alg())
                .hashed_subpackets(hashed_subpackets)
                .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                    sec_key.key_id(),
                ))])
                .build()?,
            SignatureVersion::V6 => SignatureConfigBuilder::v6()
                .typ(SignatureType::SubkeyBinding)
                .pub_alg(sec_key.algorithm())
                .hash_alg(sec_key.hash_alg())
                .hashed_subpackets(hashed_subpackets)
                .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                    sec_key.key_id(),
                ))])
                .generate_salt(rng)?
                .build()?,
            _ => unsupported_err!("unsupported signature version: {:?}", sig_version),
        };
        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key)?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}
