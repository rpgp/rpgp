use rand::{CryptoRng, Rng};

use crate::{
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::Result,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Password, PkeskBytes, PublicParams, SignatureBytes,
    },
};

pub trait KeyDetails {
    fn version(&self) -> KeyVersion;
    fn fingerprint(&self) -> Fingerprint;
    fn key_id(&self) -> KeyId;
    fn algorithm(&self) -> PublicKeyAlgorithm;
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
    fn imprint<D: KnownDigest>(&self) -> Result<generic_array::GenericArray<u8, D::OutputSize>>;
}

pub trait PublicKeyTrait: KeyDetails + std::fmt::Debug {
    fn created_at(&self) -> &chrono::DateTime<chrono::Utc>;
    fn expiration(&self) -> Option<u16>;

    /// Verify a signed message.
    /// Data will be hashed using `hash`, before verifying.
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()>;

    fn public_params(&self) -> &PublicParams;

    fn is_signing_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;

        #[cfg(feature = "draft-pqc")]
        if matches!(
            self.algorithm(),
            MlDsa65Ed25519 | MlDsa87Ed448 | SlhDsaShake128s | SlhDsaShake128f | SlhDsaShake256s
        ) {
            return true;
        }

        matches!(
            self.algorithm(),
            RSA | RSASign | Elgamal | DSA | ECDSA | EdDSALegacy | Ed25519 | Ed448
        )
    }

    fn is_encryption_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;

        #[cfg(feature = "draft-pqc")]
        if matches!(self.algorithm(), MlKem768X25519 | MlKem1024X448) {
            return true;
        }

        matches!(
            self.algorithm(),
            RSA | RSAEncrypt | ECDH | DiffieHellman | Elgamal | ElgamalEncrypt | X25519 | X448
        )
    }
}

impl<T: KeyDetails> KeyDetails for &T {
    fn version(&self) -> KeyVersion {
        (*self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (*self).fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> KeyId {
        (*self).key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (*self).algorithm()
    }
}

impl<T: PublicKeyTrait> PublicKeyTrait for &T {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        (*self).verify_signature(hash, data, sig)
    }

    fn public_params(&self) -> &PublicParams {
        (*self).public_params()
    }

    fn expiration(&self) -> Option<u16> {
        (*self).expiration()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        (*self).created_at()
    }
}

impl KeyDetails for Box<&dyn SigningKey> {
    fn version(&self) -> KeyVersion {
        (**self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (**self).fingerprint()
    }

    fn key_id(&self) -> KeyId {
        (**self).key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (**self).algorithm()
    }
}

/// Keys that can sign data.
///
/// Contains private data.
pub trait SigningKey: KeyDetails + std::fmt::Debug {
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
pub trait EncryptionKey: PublicKeyTrait {
    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes>;
}

impl<T: EncryptionKey> EncryptionKey for &T {
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        (*self).encrypt(rng, plain, typ)
    }
}
