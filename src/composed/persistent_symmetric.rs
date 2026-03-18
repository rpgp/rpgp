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
use bytes::Bytes;
use cx448::subtle::ConstantTimeEq;
use rand::Rng;

use crate::{
    armor,
    composed::ArmorOptions,
    crypto::{
        aead::AeadAlgorithm, aead_key::InfoParameter, hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq},
    packet,
    packet::{PacketTrait, SignatureVersion},
    ser::Serialize,
    types::{
        EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes,
        PlainSecretParams, PublicParams, SignatureBytes, Tag, Timestamp, VerifyingKey,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransferablePersistentSymmetricKey {
    pub key: packet::PersistentSymmetricKey,
}

impl TransferablePersistentSymmetricKey {
    pub fn to_unlockable(&self, key_pw: &Password) -> UnlockablePersistentSymmetricKey {
        UnlockablePersistentSymmetricKey {
            tpsk: self.clone(),
            key_pw: Password::Static(key_pw.read()),
        }
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
        mut rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes> {
        ensure!(
            matches!(typ, EskType::V6),
            "only v6 ESK supported right now"
        );

        let aead = AeadAlgorithm::Ocb; // FIXME: parameter

        // 32 octets of salt. The salt is used to derive the key-encryption key and MUST be
        // securely generated (see section 13.10 of [RFC9580]).
        let mut salt: [u8; 32] = [0; 32];
        rng.fill(&mut salt);

        self.tpsk.key.unlock(&self.key_pw, |pub_params, sec_params| {
            let PublicParams::AEAD(public_params) = pub_params else {
                bail!("Unsupported public parameters for persistent symmetric key: {pub_params:?}");
            };

            let PlainSecretParams::AEAD(secret) = &sec_params else {
                bail!("Unsupported secret parameters for persistent symmetric key: {sec_params:?}");
            };

            // A symmetric key encryption of the plaintext value described in section 5.1 of [RFC9580],
            // performed with the key-encryption key and IV computed as described in Section 7.4,
            // using the symmetric-key cipher of the key and the indicated AEAD mode, with as
            // additional data the empty string; including the authentication tag.

            let version = self.tpsk.key.details.version().into();
            let info = InfoParameter {
                packet_type: Tag::PublicKeyEncryptedSessionKey,
                version,
                aead,
                sym_alg: public_params.sym_alg,
            };

            let (key, iv) =
                crate::crypto::aead_key::SecretKey::derive_key_iv(&secret.key, &salt, info);

            let mut buf = plain.into();

            aead.encrypt_in_place(&public_params.sym_alg, &key, &iv, &[], &mut buf)?;

            let encrypted: Bytes = buf.into();

            Ok(PkeskBytes::Aead {
                aead,
                salt,
                encrypted,
            })
        })?
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

impl VerifyingKey for UnlockablePersistentSymmetricKey {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> crate::errors::Result<()> {
        let Some(digest_len) = hash.digest_size() else {
            bail!(
                "UnlockablePersistentSymmetricKey::verify: invalid hash algorithm: {:?}",
                hash
            );
        };
        ensure_eq!(
            data.len(),
            digest_len,
            "signature data length {} doesn't match digest len {}",
            data.len(),
            digest_len,
        );

        let SignatureBytes::PersistentSymmetric { aead, salt, tag } = sig else {
            bail!("Unsupported SignatureBytes for persistent symmetric key: {sig:?}");
        };

        ensure_eq!(
            tag.len(),
            aead.tag_size().unwrap_or(0),
            "unexpected tag length"
        );

        self.tpsk.key.unlock(&self.key_pw, |pub_params, sec_params| {
            let PublicParams::AEAD(public) = &pub_params else {
                bail!("Unsupported public parameters for persistent symmetric key: {pub_params:?}");
            };
            let PlainSecretParams::AEAD(secret) = &sec_params else {
                bail!("Unsupported secret parameters for persistent symmetric key: {sec_params:?}");
            };

            let version = SignatureVersion::V6; // FIXME: should not be fixed

            // "buf" is the newly calculated authentication tag
            let buf = secret.compute_persistent_mac(version, public.sym_alg, *aead, salt, data)?;

            // check if the stored and calculated authentication tags match
            if buf.ct_ne(&**tag).into() {
                // no: the signature is invalid!
                bail!("PersistentSymmetricKey signature mismatch");
            }

            Ok(())
        })?
    }
}
