use std::ops::Deref;

use chrono::SubsecRound;
use rand::{CryptoRng, Rng};

use crate::{
    composed::{KeyDetails, SignedPublicKey, SignedPublicSubKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{self, KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Password, PkeskBytes, PublicKeyTrait,
        PublicParams, SecretKeyTrait, SignatureBytes,
    },
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

    pub fn sign<R, K, P>(
        self,
        mut rng: R,
        sec_key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedPublicKey>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&mut rng, sec_key, pub_key, key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&mut rng, sec_key, pub_key, key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        })
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.primary_key.encrypt(rng, plain, typ)
    }
}

impl Deref for PublicKey {
    type Target = packet::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.primary_key
    }
}

impl PublicSubkey {
    pub fn new(key: packet::PublicSubkey, keyflags: KeyFlags) -> Self {
        PublicSubkey { key, keyflags }
    }

    pub fn sign<R, K, P>(
        self,
        mut rng: R,
        sec_key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedPublicSubKey>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
            Subpacket::regular(SubpacketData::KeyFlags(self.keyflags))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(sec_key.fingerprint()))?,
        ];
        let unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::Issuer(sec_key.key_id()))?];

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

        let signatures = vec![config.sign_key_binding(sec_key, pub_key, key_pw, &key)?];

        Ok(SignedPublicSubKey { key, signatures })
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.key.encrypt(rng, plain, typ)
    }
}

impl crate::types::KeyDetails for PublicSubkey {
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
}

impl PublicKeyTrait for PublicSubkey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
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
