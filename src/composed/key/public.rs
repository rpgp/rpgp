use rand::{CryptoRng, Rng};

use crate::{
    composed::SignedPublicSubKey,
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{self, KeyFlags, Signature},
    ser::Serialize,
    types::{
        Fingerprint, KeyId, Password, PublicKeyTrait, PublicParams, SecretKeyTrait, SignatureBytes,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct PublicSubkey {
    pub key: packet::PublicSubkey,
    pub keyflags: KeyFlags,

    /// Embedded primary key binding signature, required for signing-capable subkeys.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#sigtype-primary-binding>
    pub embedded: Option<Signature>,
}

impl PublicSubkey {
    /// Produce a Subkey Binding Signature (Type ID 0x18), to bind this subkey to a primary key
    pub(super) fn sign<R, K, P>(
        self,
        mut rng: R,
        primary_sec_key: &K,
        primary_pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedPublicSubKey>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let key = self.key;

        let signatures = vec![key.sign(
            &mut rng,
            primary_sec_key,
            primary_pub_key,
            key_pw,
            self.keyflags.clone(),
            self.embedded.clone(),
        )?];

        Ok(SignedPublicSubKey { key, signatures })
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
