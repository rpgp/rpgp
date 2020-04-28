use std::boxed::Box;

use rsa::hash::Hashes;
use try_from::TryInto;

use digest::{Digest, FixedOutput};
use generic_array::typenum::Unsigned;
use md5::Md5;
use ripemd160::Ripemd160;
use sha1::Sha1;

use crate::errors::{Error, Result};

/// Available hash algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.4
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum HashAlgorithm {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA2_256 = 8,
    SHA2_384 = 9,
    SHA2_512 = 10,
    SHA2_224 = 11,
    SHA3_256 = 12,
    SHA3_512 = 14,

    /// Do not use, just for compatability with GnuPG.
    Private10 = 110,
}

impl zeroize::DefaultIsZeroes for HashAlgorithm {}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::SHA2_256
    }
}

impl TryInto<Hashes> for HashAlgorithm {
    type Err = Error;

    fn try_into(self) -> Result<Hashes> {
        match self {
            HashAlgorithm::None => Err(format_err!("none")),
            HashAlgorithm::MD5 => Ok(Hashes::MD5),
            HashAlgorithm::SHA1 => Ok(Hashes::SHA1),
            HashAlgorithm::RIPEMD160 => Ok(Hashes::RIPEMD160),
            HashAlgorithm::SHA2_256 => Ok(Hashes::SHA2_256),
            HashAlgorithm::SHA2_384 => Ok(Hashes::SHA2_384),
            HashAlgorithm::SHA2_512 => Ok(Hashes::SHA2_512),
            HashAlgorithm::SHA2_224 => Ok(Hashes::SHA2_224),
            HashAlgorithm::SHA3_256 => Ok(Hashes::SHA3_256),
            HashAlgorithm::SHA3_512 => Ok(Hashes::SHA3_512),
            HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
        }
    }
}

/// Trait to work around the fact that the `Digest` trait from rustcrypto can not
/// be used as `Box<Digest>`.
pub trait Hasher {
    /// Update the hash with the given value.
    fn update(&mut self, _: &[u8]);
    /// Finalize the hash and return the result.
    fn finish(self: Box<Self>) -> Vec<u8>;
}

macro_rules! derive_hasher {
    ($name:ident, $struct:path) => {
        #[derive(Default)]
        pub struct $name {
            inner: $struct,
        }

        impl Hasher for $name {
            fn update(&mut self, data: &[u8]) {
                self.inner.input(data);
            }

            fn finish(self: Box<Self>) -> Vec<u8> {
                self.inner.result().as_slice().to_vec()
            }
        }
    };
}

derive_hasher!(Md5Hasher, Md5);
derive_hasher!(Sha1Hasher, Sha1);
derive_hasher!(Ripemd160Hasher, Ripemd160);
derive_hasher!(Sha2_256Hasher, sha2::Sha256);
derive_hasher!(Sha2_384Hasher, sha2::Sha384);
derive_hasher!(Sha2_512Hasher, sha2::Sha512);
derive_hasher!(Sha2_224Hasher, sha2::Sha224);
derive_hasher!(Sha3_256Hasher, sha3::Sha3_256);
derive_hasher!(Sha3_512Hasher, sha3::Sha3_512);

impl HashAlgorithm {
    /// Create a new hasher.
    pub fn new_hasher(self) -> Result<Box<dyn Hasher>> {
        match self {
            HashAlgorithm::MD5 => Ok(Box::new(Md5Hasher::default())),
            HashAlgorithm::SHA1 => Ok(Box::new(Sha1Hasher::default())),
            HashAlgorithm::RIPEMD160 => Ok(Box::new(Ripemd160Hasher::default())),
            HashAlgorithm::SHA2_256 => Ok(Box::new(Sha2_256Hasher::default())),
            HashAlgorithm::SHA2_384 => Ok(Box::new(Sha2_384Hasher::default())),
            HashAlgorithm::SHA2_512 => Ok(Box::new(Sha2_512Hasher::default())),
            HashAlgorithm::SHA2_224 => Ok(Box::new(Sha2_224Hasher::default())),
            HashAlgorithm::SHA3_256 => Ok(Box::new(Sha3_256Hasher::default())),
            HashAlgorithm::SHA3_512 => Ok(Box::new(Sha3_512Hasher::default())),

            _ => unimplemented_err!("hasher {:?}", self),
        }
    }

    /// Calculate the digest of the given input data.
    pub fn digest(self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            HashAlgorithm::MD5 => Md5::digest(data).to_vec(),
            HashAlgorithm::SHA1 => Sha1::digest(data).to_vec(),
            HashAlgorithm::RIPEMD160 => Ripemd160::digest(data).to_vec(),
            HashAlgorithm::SHA2_256 => sha2::Sha256::digest(data).to_vec(),
            HashAlgorithm::SHA2_384 => sha2::Sha384::digest(data).to_vec(),
            HashAlgorithm::SHA2_512 => sha2::Sha512::digest(data).to_vec(),
            HashAlgorithm::SHA2_224 => sha2::Sha224::digest(data).to_vec(),
            HashAlgorithm::SHA3_256 => sha3::Sha3_256::digest(data).to_vec(),
            HashAlgorithm::SHA3_512 => sha3::Sha3_512::digest(data).to_vec(),

            HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
            _ => unimplemented_err!("hasher: {:?}", self),
        })
    }

    /// Returns the expected digest size for the given algorithm.
    pub fn digest_size(self) -> usize {
        match self {
            HashAlgorithm::MD5 => <Md5 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA1 => <Sha1 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::RIPEMD160 => <Ripemd160 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA2_256 => <sha2::Sha256 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA2_384 => <sha2::Sha384 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA2_512 => <sha2::Sha512 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA2_224 => <sha2::Sha224 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA3_256 => <sha3::Sha3_256 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA3_512 => <sha3::Sha3_512 as FixedOutput>::OutputSize::to_usize(),
            _ => 0,
        }
    }
}
