use aes_gcm::aead::rand_core::CryptoRng;

use crate::{
    composed::{KeyDetails, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey},
    errors::Result,
    packet::{self, KeyFlags, Signature},
    types::Password,
};

/// Internal building block to represent the components of a "Transferable Secret Key (TSK)"
/// (but without any Signature packets)
#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct RawSecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<(packet::PublicSubkey, KeyFlags, Option<Signature>)>,
    secret_subkeys: Vec<(packet::SecretSubkey, KeyFlags, Option<Signature>)>,
}

impl RawSecretKey {
    pub(super) fn new(
        primary_key: packet::SecretKey,
        details: KeyDetails,
        public_subkeys: Vec<(packet::PublicSubkey, KeyFlags, Option<Signature>)>,
        secret_subkeys: Vec<(packet::SecretSubkey, KeyFlags, Option<Signature>)>,
    ) -> Self {
        RawSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    pub(super) fn sign<R>(self, rng: &mut R, key_pw: &Password) -> Result<SignedSecretKey>
    where
        R: CryptoRng + ?Sized,
    {
        let primary_key = self.primary_key;
        let details = self
            .details
            .sign(rng, &primary_key, primary_key.public_key(), key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|(sub_key, keyflags, embedded)| {
                // Produce a Subkey Binding Signature (Type ID 0x18), to bind this subkey to a primary key
                let signature = sub_key.sign(
                    rng,
                    &primary_key,
                    primary_key.public_key(),
                    key_pw,
                    keyflags,
                    embedded,
                )?;
                Ok(SignedPublicSubKey {
                    key: sub_key,
                    signatures: vec![signature],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|(sub_key, keyflags, embedded)| {
                // Produce a Subkey Binding Signature (Type ID 0x18), to bind this subkey to a primary key
                let signature = sub_key.sign(
                    rng,
                    &primary_key,
                    primary_key.public_key(),
                    key_pw,
                    keyflags,
                    embedded,
                )?;
                Ok(SignedSecretSubKey {
                    key: sub_key,
                    signatures: vec![signature],
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}

#[cfg(test)]
mod tests {
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

        secret.verify_bindings().unwrap();
        public.verify_bindings().unwrap();

        let signed_pubkey = secret.to_public_key();

        assert_eq!(signed_pubkey.primary_key, public.primary_key);
    }
}
