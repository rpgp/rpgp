#![cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys")]

//! Transferable Persistent Symmetric Key
//!
//! This is a thin wrapper around the [`PersistentSymmetricKey`] packet type.
//!
//! Ref <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html>

use std::{
    fmt::{Debug, Formatter},
    io,
};

use aead::rand_core::CryptoRng;
use rand::Rng;

use crate::{
    armor,
    composed::ArmorOptions,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet,
    packet::{PacketTrait, PersistentSymmetricKey},
    ser::Serialize,
    types::{
        EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes,
        PublicParams, SignatureBytes, Timestamp, VerifyingKey,
    },
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
    pub fn to_unlockable(&self, key_pw: &Password) -> UnlockablePersistentSymmetricKey {
        UnlockablePersistentSymmetricKey {
            tpsk: self.clone(),
            key_pw: Password::Static(key_pw.read()),
        }
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

/// A wrapper around `TransferablePersistentSymmetricKey` that bundles a symmetric key with a `Password`
///
/// This allows performing "public key operations" (i.e. encryption and signature verification) on persistent symmetric keys that are password-locked.
pub struct UnlockablePersistentSymmetricKey {
    tpsk: TransferablePersistentSymmetricKey,
    key_pw: Password,
}

impl UnlockablePersistentSymmetricKey {
    pub fn new(tpsk: TransferablePersistentSymmetricKey, key_pw: Password) -> Self {
        Self { tpsk, key_pw }
    }
}

impl EncryptionKey for UnlockablePersistentSymmetricKey {
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes> {
        let aead = AeadAlgorithm::Ocb; // FIXME: parameter

        self.tpsk.key.symmetric_encrypt(
            rng,
            &self.key_pw,
            plain,
            typ,
            aead,
            self.tpsk.key.details.version(),
        )
    }
}

impl VerifyingKey for UnlockablePersistentSymmetricKey {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> crate::errors::Result<()> {
        self.tpsk
            .key
            .symmetric_verify(&self.key_pw, hash, data, sig)
    }
}

impl KeyDetails for UnlockablePersistentSymmetricKey {
    fn version(&self) -> KeyVersion {
        self.tpsk.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.tpsk.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.tpsk.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.tpsk.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.tpsk.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.tpsk.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.tpsk.key.public_params()
    }
}

impl Debug for UnlockablePersistentSymmetricKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.tpsk.fmt(f)
    }
}
