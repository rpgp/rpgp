use std::collections::BTreeMap;
use std::io;

use rand::{CryptoRng, Rng};

use crate::armor;
use crate::composed::key::{PublicKey, PublicSubkey};
use crate::composed::signed_key::SignedKeyDetails;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::HashAlgorithm;
use crate::errors::Result;
use crate::packet::{self, write_packet, SignatureType};
use crate::ser::Serialize;
use crate::types::{KeyId, KeyTrait, Mpi, PublicKeyTrait};

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
        mut public_subkeys: Vec<SignedPublicSubKey>,
    ) -> Self {
        public_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

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
        self.details.verify(&self.primary_key)?;
        self.verify_public_subkeys()?;

        Ok(())
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        headers: Option<&BTreeMap<String, String>>,
    ) -> Result<()> {
        armor::write(self, armor::BlockType::PublicKey, writer, headers)
    }

    pub fn to_armored_bytes(&self, headers: Option<&BTreeMap<String, String>>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, headers)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, headers: Option<&BTreeMap<String, String>>) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes(headers)?)?.to_string())
    }

    pub fn as_unsigned(&self) -> PublicKey {
        PublicKey::new(
            self.primary_key.clone(),
            self.details.as_unsigned(),
            self.public_subkeys
                .iter()
                .map(SignedPublicSubKey::as_unsigned)
                .collect(),
        )
    }
}

impl KeyTrait for SignedPublicKey {
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
}

impl PublicKeyTrait for SignedPublicKey {
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.primary_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.primary_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.primary_key.to_writer_old(writer)
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
    pub fn new(key: packet::PublicSubkey, mut signatures: Vec<packet::Signature>) -> Self {
        signatures.retain(|sig| {
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
        });

        SignedPublicSubKey { key, signatures }
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");
        for sig in &self.signatures {
            sig.verify_key_binding(key, &self.key)?;
        }

        Ok(())
    }
    pub fn as_unsigned(&self) -> PublicSubkey {
        let keyflags = self
            .signatures
            .first()
            .expect("missing signatures")
            .key_flags();

        PublicSubkey::new(self.key.clone(), keyflags)
    }
}

impl KeyTrait for SignedPublicSubKey {
    /// Returns the fingerprint of the key.
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}

impl PublicKeyTrait for SignedPublicSubKey {
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.key.to_writer_old(writer)
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
