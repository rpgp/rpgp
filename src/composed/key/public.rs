use std::io;

use chrono::SubsecRound;
use rand::{CryptoRng, Rng};

use crate::composed::{KeyDetails, SignedPublicKey, SignedPublicSubKey};
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{self, KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use crate::types::PkeskBytes;
use crate::types::{
    EskType, Fingerprint, KeyId, KeyVersion, PublicKeyTrait, PublicParams, SecretKeyTrait,
    SignatureBytes,
};

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    primary_key: packet::PublicKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
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

    pub fn sign<R, F>(
        self,
        mut rng: R,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<SignedPublicKey>
    where
        R: CryptoRng + Rng,
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&mut rng, sec_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, sec_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        })
    }
}

impl PublicKeyTrait for PublicKey {
    fn version(&self) -> crate::types::KeyVersion {
        self.primary_key.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.primary_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.primary_key.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()> {
        self.primary_key.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.primary_key.public_params()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.primary_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.primary_key.expiration()
    }
}

impl PublicSubkey {
    pub fn new(key: packet::PublicSubkey, keyflags: KeyFlags) -> Self {
        PublicSubkey { key, keyflags }
    }

    pub fn sign<R, F>(
        self,
        mut rng: R,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<SignedPublicSubKey>
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
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(sec_key.key_id()))];

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

        config.hashed_subpackets = hashed_subpackets;
        config.unhashed_subpackets = unhashed_subpackets;

        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key)?];

        Ok(SignedPublicSubKey { key, signatures })
    }
}

impl PublicKeyTrait for PublicSubkey {
    fn version(&self) -> crate::types::KeyVersion {
        self.key.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.key.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()> {
        self.key.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.key.expiration()
    }
}
