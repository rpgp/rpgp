#![cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys-03")]

//! Transferable Persistent Symmetric Key
//!
//! This is a thin wrapper around the [`PersistentSymmetricKey`] packet type.
//!
//! Ref <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html>

use std::{fmt::Debug, io};

use aead::rand_core::CryptoRng;
use rand::Rng;

use crate::{
    armor,
    composed::ArmorOptions,
    crypto::{aead::AeadAlgorithm, public_key::PublicKeyAlgorithm},
    packet,
    packet::{
        PacketTrait, PersistentSymmetricEncryptionKey, PersistentSymmetricKey,
        PersistentSymmetricSigningKey, PersistentSymmetricVerifyingKey,
    },
    ser::Serialize,
    types::{Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PublicParams, Timestamp},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransferablePersistentSymmetricKey {
    pub(crate) key: packet::PersistentSymmetricKey,
}

impl From<PersistentSymmetricKey> for TransferablePersistentSymmetricKey {
    fn from(key: PersistentSymmetricKey) -> Self {
        Self { key }
    }
}

impl TransferablePersistentSymmetricKey {
    pub fn into_encryptor(
        self,
        key_pw: Password,
        aead: AeadAlgorithm,
    ) -> PersistentSymmetricEncryptionKey {
        PersistentSymmetricEncryptionKey::new(self.key, key_pw, aead)
    }

    pub fn into_signer<R: CryptoRng + Rng>(
        self,
        rng: R,
        aead: AeadAlgorithm,
    ) -> PersistentSymmetricSigningKey<R> {
        PersistentSymmetricSigningKey::new(self.key, rng, aead)
    }

    pub fn into_verifier(self, key_pw: Password) -> PersistentSymmetricVerifyingKey {
        PersistentSymmetricVerifyingKey::new(self.key, key_pw)
    }

    pub fn key(&self) -> &PersistentSymmetricKey {
        &self.key
    }

    pub fn key_mut(&mut self) -> &mut PersistentSymmetricKey {
        &mut self.key
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        opts: ArmorOptions<'_>,
    ) -> crate::errors::Result<()> {
        armor::write(
            self,
            armor::BlockType::PrivateKey,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> crate::errors::Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, opts)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> crate::errors::Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }
}

impl Serialize for TransferablePersistentSymmetricKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        self.key.to_writer_with_header(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.write_len_with_header()
    }
}

impl KeyDetails for TransferablePersistentSymmetricKey {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}
