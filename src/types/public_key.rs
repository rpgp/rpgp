use std::io;

use rand::{CryptoRng, Rng};

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::types::{Fingerprint, KeyId, KeyVersion, PublicParams, SignatureBytes};
use crate::EskBytes;

pub trait PublicKeyTrait: std::fmt::Debug {
    fn version(&self) -> KeyVersion;

    fn fingerprint(&self) -> Fingerprint;

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> KeyId;

    fn algorithm(&self) -> PublicKeyAlgorithm;

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

    /// Encrypt the given `plain` for this key.
    fn encrypt<R: CryptoRng + Rng>(&self, rng: R, plain: &[u8], v6_esk: bool) -> Result<EskBytes>;

    // TODO: figure out a better place for this
    /// This is the data used for hashing in a signature. Only uses the public portion of the key.
    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()>;

    fn public_params(&self) -> &PublicParams;

    fn is_signing_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;
        matches!(
            self.algorithm(),
            RSA | RSASign | ElgamalSign | DSA | ECDSA | EdDSALegacy
        )
    }

    fn is_encryption_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;

        matches!(
            self.algorithm(),
            RSA | RSAEncrypt | ECDH | DiffieHellman | Elgamal
        )
    }
}

impl<'a, T: PublicKeyTrait> PublicKeyTrait for &'a T {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        (*self).verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(&self, rng: R, plain: &[u8], v6_esk: bool) -> Result<EskBytes> {
        (*self).encrypt(rng, plain, v6_esk)
    }

    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()> {
        (*self).serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        (*self).public_params()
    }
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

    fn expiration(&self) -> Option<u16> {
        (*self).expiration()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        (*self).created_at()
    }
}
