use std::ops::Deref;

use rand::{CryptoRng, RngCore};

use crate::{
    composed::{KeyDetails, SignedPublicKey, SignedPublicSubKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{self, KeyFlags, Signature},
    ser::Serialize,
    types::{
        EskType, Fingerprint, KeyId, Password, PkeskBytes, PublicKeyTrait, PublicParams,
        SecretKeyTrait, SignatureBytes,
    },
};

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    pub primary_key: packet::PublicKey,
    pub details: KeyDetails,
    pub public_subkeys: Vec<PublicSubkey>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicSubkey {
    pub key: packet::PublicSubkey,
    pub keyflags: KeyFlags,

    /// Embedded primary key binding signature, required for signing-capable subkeys.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#sigtype-primary-binding>
    pub embedded: Option<Signature>,
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
        rng: &mut R,
        sec_key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedPublicKey>
    where
        R: CryptoRng + RngCore + ?Sized,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(rng, sec_key, pub_key, key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(rng, sec_key, pub_key, key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        })
    }

    pub fn encrypt<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
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
    pub fn new(key: packet::PublicSubkey, keyflags: KeyFlags, embedded: Option<Signature>) -> Self {
        PublicSubkey {
            key,
            keyflags,
            embedded,
        }
    }

    /// Produce a Subkey Binding Signature (Type ID 0x18), to bind this subkey to a primary key
    pub fn sign<R, K, P>(
        self,
        rng: &mut R,
        primary_sec_key: &K,
        primary_pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedPublicSubKey>
    where
        R: CryptoRng + RngCore + ?Sized,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let key = self.key;

        let signatures = vec![key.sign(
            rng,
            primary_sec_key,
            primary_pub_key,
            key_pw,
            self.keyflags,
            self.embedded,
        )?];

        Ok(SignedPublicSubKey { key, signatures })
    }

    pub fn encrypt<R: RngCore + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
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
