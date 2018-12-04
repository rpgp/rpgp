use std::io;

use composed::key::{SignedKeyDetails, SignedPublicSubKey};
use errors::Result;
use packet::{self, SignatureType};
use ser::Serialize;
use types::{KeyId, KeyTrait, PublicKeyTrait, SecretKeyRepr, SecretKeyTrait};

/// Represents a secret signed PGP key.
#[derive(Debug, PartialEq, Eq)]
pub struct SignedSecretKey {
    pub primary_key: packet::SecretKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
    pub secret_subkeys: Vec<SignedSecretSubKey>,
}

key_parser!(
    SignedSecretKey,
    SignedSecretKeyParser,
    Tag::SecretKey,
    packet::SecretKey,
    // secret keys, can contain both public and secret subkeys
    (
        PublicSubkey,
        packet::PublicSubkey,
        SignedPublicSubKey,
        public_subkeys
    ),
    (
        SecretSubkey,
        packet::SecretSubkey,
        SignedSecretSubKey,
        secret_subkeys
    )
);

impl SignedSecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: SignedKeyDetails,
        public_subkeys: Vec<SignedPublicSubKey>,
        secret_subkeys: Vec<SignedSecretSubKey>,
    ) -> Self {
        let public_subkeys = public_subkeys
            .into_iter()
            .filter(|key| {
                if key.signatures.is_empty() {
                    warn!("ignoring unsigned {:?}", key.key);
                    false
                } else {
                    true
                }
            })
            .collect();

        let secret_subkeys = secret_subkeys
            .into_iter()
            .filter(|key| {
                if key.signatures.is_empty() {
                    warn!("ignoring unsigned {:?}", key.key);
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }
    fn verify_public_subkeys(&self) -> Result<()> {
        for subkey in &self.public_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    fn verify_secret_subkeys(&self) -> Result<()> {
        for subkey in &self.secret_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.details.verify(&self.primary_key)?;
        self.verify_public_subkeys()?;
        self.verify_secret_subkeys()?;

        Ok(())
    }
}

impl KeyTrait for SignedSecretKey {
    /// Returns the fingerprint of the associated primary key.
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> Option<KeyId> {
        self.primary_key.key_id()
    }
}

impl Serialize for SignedSecretKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!()
    }
}

impl SecretKeyTrait for SignedSecretKey {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        self.primary_key.unlock(pw, work)
    }
}

/// Represents a composed secret PGP SubKey.
#[derive(Debug, PartialEq, Eq)]
pub struct SignedSecretSubKey {
    pub key: packet::SecretSubkey,
    pub signatures: Vec<packet::Signature>,
}

impl SignedSecretSubKey {
    pub fn new(key: packet::SecretSubkey, signatures: Vec<packet::Signature>) -> Self {
        let signatures = signatures
            .into_iter()
            .filter(|sig| {
                if sig.typ != SignatureType::SubkeyBinding
                    && sig.typ != SignatureType::SubkeyRevocation
                {
                    warn!(
                        "ignoring unexpected signature {:?} after Subkey packet",
                        sig.typ
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedSecretSubKey { key, signatures }
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");

        for sig in &self.signatures {
            sig.verify_key_binding(key, &self.key)?;
        }

        Ok(())
    }
}

impl KeyTrait for SignedSecretSubKey {
    /// Returns the fingerprint of the key.
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    fn key_id(&self) -> Option<KeyId> {
        self.key.key_id()
    }
}

impl Serialize for SignedSecretSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!()
    }
}

impl SecretKeyTrait for SignedSecretSubKey {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        self.key.unlock(pw, work)
    }
}
