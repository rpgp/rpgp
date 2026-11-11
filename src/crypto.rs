//! Low-level cryptographic building blocks

use zeroize::Zeroizing;

use self::hash::HashAlgorithm;
use crate::types::SignatureBytes;

// Symmetric

pub mod aead;
pub mod aes_kw;
pub mod sym;

// Encryption & Signing

pub mod dsa;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod ed448;
pub mod eddsa_legacy;
pub mod elgamal;
pub mod rsa;
pub mod x25519;
pub mod x448;

// PQC

#[cfg(feature = "pqc")]
pub mod ml_dsa65_ed25519;
#[cfg(feature = "pqc")]
pub mod ml_dsa87_ed448;
#[cfg(feature = "pqc")]
pub mod ml_kem1024_x448;
#[cfg(feature = "pqc")]
pub mod ml_kem768_x25519;
#[cfg(feature = "pqc")]
pub mod slh_dsa_shake128f;
#[cfg(feature = "pqc")]
pub mod slh_dsa_shake128s;
#[cfg(feature = "pqc")]
pub mod slh_dsa_shake256s;

// PQC draft-ietf-openpgp-nist-bp-comp

// 100 	ML-KEM-768+ECDH-NIST-P-384
#[cfg(feature = "pqc-nist-bp")]
pub mod ml_kem768_nistp384;

// 101 	ML-KEM-1024+ECDH-NIST-P-521
#[cfg(feature = "pqc-nist-bp")]
pub mod ml_kem1024_nistp521;

// 104 ML-DSA-65+ECDSA-NIST-P-384
#[cfg(feature = "pqc-nist-bp")]
pub mod ml_dsa65_nistp384;

// 105 ML-DSA-87+ECDSA-NIST-P-521
#[cfg(feature = "pqc-nist-bp")]
pub mod ml_dsa87_nistp521;

// Misc

pub mod checksum;
pub mod ecc_curve;
pub mod hash;
pub mod public_key;

/// Describes keys that can decrypt data.
pub trait Decryptor {
    type EncryptionFields<'a>;

    fn decrypt(
        &self,
        data: Self::EncryptionFields<'_>,
    ) -> crate::errors::Result<Zeroizing<Vec<u8>>>;
}

/// Describes keys that can sign data.
pub trait Signer {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> crate::errors::Result<SignatureBytes>;
}
