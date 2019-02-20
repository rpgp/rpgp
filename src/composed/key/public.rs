use std::io;

use armor;
use composed::key::SignedKeyDetails;
use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use packet::{self, write_packet, SignatureType};
use ser::Serialize;
use types::{KeyId, KeyTrait, PublicKeyTrait};

/// Represents a Public PGP key, which is signed and either received or ready to be transferred.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedPublicKey {
    pub primary_key: packet::PublicKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
}

key_parser!(
    SignedPublicKey,
    PublicKeyParser,
    Tag::PublicKey,
    packet::PublicKey,
    (
        PublicSubkey,
        packet::PublicSubkey,
        SignedPublicSubKey,
        public_subkeys
    )
);

impl SignedPublicKey {
    pub fn new(
        primary_key: packet::PublicKey,
        details: SignedKeyDetails,
        public_subkeys: Vec<SignedPublicSubKey>,
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

        SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        }
    }

    fn verify_public_subkeys(&self) -> Result<()> {
        for subkey in &self.public_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_public_subkeys()?;
        self.details.verify(&self.primary_key)?;

        Ok(())
    }

    pub fn to_armored_writer(&self, writer: &mut impl io::Write) -> Result<()> {
        armor::write(self, "PUBLIC KEY", writer)
    }

    pub fn to_armored_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes()?)?.to_string())
    }
}

impl KeyTrait for SignedPublicKey {
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

impl Serialize for SignedPublicKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.primary_key)?;
        self.details.to_writer(writer)?;
        for ps in &self.public_subkeys {
            ps.to_writer(writer)?;
        }

        Ok(())
    }
}

/// Represents a Public PGP SubKey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedPublicSubKey {
    pub key: packet::PublicSubkey,
    pub signatures: Vec<packet::Signature>,
}

impl SignedPublicSubKey {
    pub fn new(key: packet::PublicSubkey, signatures: Vec<packet::Signature>) -> Self {
        let signatures = signatures
            .into_iter()
            .filter(|sig| {
                if sig.typ() != SignatureType::SubkeyBinding
                    && sig.typ() != SignatureType::SubkeyRevocation
                {
                    warn!(
                        "ignoring unexpected signature {:?} after Subkey packet",
                        sig.typ()
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedPublicSubKey { key, signatures }
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");
        for sig in &self.signatures {
            sig.verify_key_binding(key, &self.key)?;
        }

        Ok(())
    }
}

impl KeyTrait for SignedPublicSubKey {
    /// Returns the fingerprint of the key.
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    fn key_id(&self) -> Option<KeyId> {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}

impl Serialize for SignedPublicSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.key)?;
        for sig in &self.signatures {
            write_packet(writer, sig)?;
        }

        Ok(())
    }
}
