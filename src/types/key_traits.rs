use crate::{
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::Result,
    types::{Fingerprint, KeyId, KeyVersion, Password, PublicParams, SignatureBytes},
};

pub trait KeyDetails {
    fn version(&self) -> KeyVersion;
    fn fingerprint(&self) -> Fingerprint;
    fn key_id(&self) -> KeyId;
    fn algorithm(&self) -> PublicKeyAlgorithm;
}

pub trait Imprint {
    /// An imprint of a public key packet is a generalisation of a fingerprint.
    ///
    /// It is calculated in the same way as the fingerprint, except that it MAY use a
    /// digest algorithm other than the one specified for the fingerprint.
    ///
    /// See <https://www.ietf.org/archive/id/draft-ietf-openpgp-replacementkey-03.html#name-key-imprints>
    ///
    /// NOTE: Imprints are intended as a special purpose tool. For most use cases, the OpenPGP
    /// fingerprint is the most appropriate identifier for a certificate or a component key.
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
        matches!(
            self.algorithm(),
            RSA | RSASign | Elgamal | DSA | ECDSA | EdDSALegacy | Ed25519 | Ed448
        )
    }

    fn is_encryption_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;

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

impl KeyDetails for Box<&dyn SecretKeyTrait> {
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

impl SecretKeyTrait for Box<&dyn SecretKeyTrait> {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (**self).create_signature(key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        (**self).hash_alg()
    }
}

pub trait SecretKeyTrait: KeyDetails + std::fmt::Debug {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;

    /// The recommended hash algorithm to calculate the signature hash digest with,
    /// when using this as a signer
    fn hash_alg(&self) -> HashAlgorithm;
}
