use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::types::KeyId;

use super::KeyVersion;

pub trait KeyTrait: ::std::fmt::Debug {
    fn version(&self) -> KeyVersion;

    fn fingerprint(&self) -> Vec<u8>;

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> KeyId;

    fn algorithm(&self) -> PublicKeyAlgorithm;

    fn is_signing_key(&self) -> bool {
        use crate::crypto::public_key::PublicKeyAlgorithm::*;
        matches!(
            self.algorithm(),
            RSA | RSASign | ElgamalSign | DSA | ECDSA | EdDSA
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

impl<'a, T: KeyTrait> KeyTrait for &'a T {
    fn version(&self) -> KeyVersion {
        (*self).version()
    }

    fn fingerprint(&self) -> Vec<u8> {
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
