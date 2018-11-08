use std::boxed::Box;

use digest::{Digest, FixedOutput};
use generic_array::typenum::Unsigned;
use md5::Md5;
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use errors::Result;

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available hash algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.4
pub enum HashAlgorithm {
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
}
}

/// Trait to work around the fact that the `Digest` trait from rustcrypto can not
/// be used as `Box<Digest>`.
pub trait Hasher {
    /// Update the hash with the given value.
    fn update(&mut self, &[u8]);
    /// Finalize the hash and return the result.
    fn finish(self: Box<Self>) -> Vec<u8>;
}

macro_rules! derive_hasher {
    ($name:ident, $struct:ident) => {
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
derive_hasher!(Sha256Hasher, Sha256);
derive_hasher!(Sha384Hasher, Sha384);
derive_hasher!(Sha512Hasher, Sha512);
derive_hasher!(Sha224Hasher, Sha224);

impl HashAlgorithm {
    /// Create a new hasher.
    pub fn new(&self) -> Box<Hasher> {
        match self {
            HashAlgorithm::MD5 => Box::new(Md5Hasher::default()),
            HashAlgorithm::SHA1 => Box::new(Sha1Hasher::default()),
            HashAlgorithm::RIPEMD160 => Box::new(Ripemd160Hasher::default()),
            HashAlgorithm::SHA256 => Box::new(Sha256Hasher::default()),
            HashAlgorithm::SHA384 => Box::new(Sha384Hasher::default()),
            HashAlgorithm::SHA512 => Box::new(Sha512Hasher::default()),
            HashAlgorithm::SHA224 => Box::new(Sha224Hasher::default()),
        }
    }

    /// Calculate the digest of the given input data.
    pub fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            HashAlgorithm::MD5 => Md5::digest(data).to_vec(),
            HashAlgorithm::SHA1 => Sha1::digest(data).to_vec(),
            HashAlgorithm::RIPEMD160 => Ripemd160::digest(data).to_vec(),
            HashAlgorithm::SHA256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::SHA384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::SHA512 => Sha512::digest(data).to_vec(),
            HashAlgorithm::SHA224 => Sha224::digest(data).to_vec(),
        })
    }

    /// Returns the expected digest size for the given algorithm.
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::MD5 => <Md5 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA1 => <Sha1 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::RIPEMD160 => <Ripemd160 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA256 => <Sha256 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA384 => <Sha384 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA512 => <Sha512 as FixedOutput>::OutputSize::to_usize(),
            HashAlgorithm::SHA224 => <Sha224 as FixedOutput>::OutputSize::to_usize(),
        }
    }
}
