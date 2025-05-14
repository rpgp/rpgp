use rand::CryptoRng;

use crate::{
    composed::PlainSessionKey,
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::Result,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Password, PkeskBytes, PublicParams,
        SignatureBytes, Timestamp,
    },
};

pub trait KeyDetails: std::fmt::Debug {
    /// Returns the [`KeyVersion`] of this key.
    fn version(&self) -> KeyVersion;

    /// Returns the [`KeyId`] for this key.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4>
    fn legacy_key_id(&self) -> KeyId;

    /// Returns the [`Fingerprint`] for this key.
    fn fingerprint(&self) -> Fingerprint;

    /// Returns the algorithm for this key.
    fn algorithm(&self) -> PublicKeyAlgorithm;
    fn created_at(&self) -> Timestamp;
    fn expiration(&self) -> Option<u16>;

    /// Returns the parameters for the public portion of this key.
    fn public_params(&self) -> &PublicParams;
}

pub trait Imprint {
    /// An imprint is a shorthand identifier for a key.
    ///
    /// The imprint is a generalization of the
    /// [OpenPGP fingerprint](https://www.rfc-editor.org/rfc/rfc9580.html#key-ids-fingerprints).
    /// It is calculated over the public key parameters and other non-secret inputs (depending on
    /// the key version), in the same way as the fingerprint.
    /// However, the imprint may use a digest algorithm other than the one specified for the
    /// fingerprint of the given key version.
    ///
    /// See <https://www.ietf.org/archive/id/draft-ietf-openpgp-replacementkey-03.html#name-key-imprints>
    ///
    /// NOTE: Imprints are a special purpose tool! For most use cases, the OpenPGP fingerprint is
    /// the most appropriate identifier for a certificate or a component key.
    fn imprint<D: KnownDigest>(&self) -> Result<hybrid_array::Array<u8, D::OutputSize>>;
}

/// Keys that can verify signatures.
pub trait VerifyingKey: KeyDetails {
    /// Verify a signed message.
    /// Data will be hashed using `hash`, before verifying.
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &SignatureBytes) -> Result<()>;
}

impl<T: KeyDetails> KeyDetails for &T {
    fn version(&self) -> KeyVersion {
        (*self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (*self).fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        (*self).legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (*self).algorithm()
    }

    fn expiration(&self) -> Option<u16> {
        (*self).expiration()
    }

    fn created_at(&self) -> Timestamp {
        (*self).created_at()
    }

    fn public_params(&self) -> &PublicParams {
        (*self).public_params()
    }
}

impl<T: VerifyingKey> VerifyingKey for &T {
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &SignatureBytes) -> Result<()> {
        (*self).verify(hash, data, sig)
    }
}

impl KeyDetails for Box<&dyn SigningKey> {
    fn version(&self) -> KeyVersion {
        (**self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (**self).fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        (**self).legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (**self).algorithm()
    }

    fn expiration(&self) -> Option<u16> {
        (**self).expiration()
    }

    fn created_at(&self) -> Timestamp {
        (**self).created_at()
    }

    fn public_params(&self) -> &PublicParams {
        (**self).public_params()
    }
}

/// Keys that can sign data.
///
/// Contains private data.
pub trait SigningKey: KeyDetails {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;

    /// The recommended hash algorithm to calculate the signature hash digest with,
    /// when using this as a signer
    fn hash_alg(&self) -> HashAlgorithm;
}

impl SigningKey for Box<&dyn SigningKey> {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (**self).sign(key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        (**self).hash_alg()
    }
}

/// Describes keys that can encrypt plain data (i.e. a session key) into data for a
/// [PKESK](https://www.rfc-editor.org/rfc/rfc9580#name-public-key-encrypted-sessio).
pub trait EncryptionKey: KeyDetails {
    fn encrypt<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes>;
}

impl<T: EncryptionKey> EncryptionKey for &T {
    fn encrypt<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        (*self).encrypt(rng, plain, typ)
    }
}

/// A key that can decrypt encrypted data (i.e. an encrypted session key) from a
/// [PKESK](https://www.rfc-editor.org/rfc/rfc9580#name-public-key-encrypted-sessio).
pub trait DecryptionKey: KeyDetails {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>>;
}

impl<T: DecryptionKey> DecryptionKey for &T {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        (*self).decrypt(key_pw, values, typ)
    }
}
