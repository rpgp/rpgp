use aes_gcm::aead::rand_core::CryptoRng;
use rand::RngCore;

use crate::{
    composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey},
    errors::Result,
    packet::{self, KeyFlags, Signature},
    ser::Serialize,
    types::{Password, PublicKeyTrait, SecretKeyTrait},
};

/// User facing interface to work with the components of a "Transferable Secret Key (TSK)"
/// (but without any Signature packets)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
    secret_subkeys: Vec<SecretSubkey>,
}

/// Wrapper for a SecretSubkey packet with associated KeyFlags
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretSubkey {
    key: packet::SecretSubkey,
    keyflags: KeyFlags,

    /// Embedded primary key binding signature, required for signing-capable subkeys.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#sigtype-primary-binding>
    pub embedded: Option<Signature>,
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

    pub fn sign<R>(self, rng: &mut R, key_pw: &Password) -> Result<SignedSecretKey>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let primary_key = self.primary_key;
        let details = self
            .details
            .sign(rng, &primary_key, primary_key.public_key(), key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(rng, &primary_key, primary_key.public_key(), key_pw))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(rng, &primary_key, primary_key.public_key(), key_pw))
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
    pub fn new(key: packet::SecretSubkey, keyflags: KeyFlags, embedded: Option<Signature>) -> Self {
        SecretSubkey {
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
    ) -> Result<SignedSecretSubKey>
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

        Ok(SignedSecretSubKey { key, signatures })
    }
}

#[cfg(test)]
mod tests {
    use chacha20::ChaCha8Rng;
    use rand::SeedableRng;

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
