use std::io;

use chrono::SubsecRound;
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

use crate::composed::{KeyDetails, SignedPublicKey, SignedPublicSubKey};
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    self, KeyFlags, SignatureConfigBuilder, SignatureType, Subpacket, SubpacketData,
};
use crate::types::{KeyId, Mpi, PublicKeyTrait, PublicParams, SecretKeyTrait};

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

impl PublicKeyTrait for PublicKey {
    fn version(&self) -> crate::types::KeyVersion {
        self.primary_key.version()
    }

    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.primary_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.primary_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.primary_key.to_writer_old(writer)
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

    pub fn sign<F>(self, sec_key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedPublicSubKey>
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
            .hash_alg(sec_key.hash_alg())
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                sec_key.key_id(),
            ))])
            .build()?;

        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key)?];

        Ok(SignedPublicSubKey { key, signatures })
    }
}

impl PublicKeyTrait for PublicSubkey {
    fn version(&self) -> crate::types::KeyVersion {
        self.key.version()
    }

    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.key.to_writer_old(writer)
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
