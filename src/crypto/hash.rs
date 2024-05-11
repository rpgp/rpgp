use std::{fmt::Display, str::FromStr};

use digest::Digest;
use md5::Md5;
use num_enum::{FromPrimitive, IntoPrimitive};
use ripemd::Ripemd160;
use sha1::Sha1;

use crate::errors::{Error, Result};

/// Available hash algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.4
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive, Hash)]
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

    /// Do not use, just for compatibility with GnuPG.
    Private10 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::SHA2_256
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "MD5" => Ok(Self::MD5),
            "SHA1" => Ok(Self::SHA1),
            "RIPEMD160" => Ok(Self::RIPEMD160),
            "SHA256" => Ok(Self::SHA2_256),
            "SHA384" => Ok(Self::SHA2_384),
            "SHA512" => Ok(Self::SHA2_512),
            "SHA224" => Ok(Self::SHA2_224),
            "SHA3-256" => Ok(Self::SHA3_256),
            "SHA3-512" => Ok(Self::SHA3_512),
            "Private10" => Ok(Self::Private10),
            _ => bail!("unknown hash"),
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MD5 => "MD5",
            Self::SHA1 => "SHA1",
            Self::RIPEMD160 => "RIPEMD160",
            Self::SHA2_256 => "SHA256",
            Self::SHA2_384 => "SHA384",
            Self::SHA2_512 => "SHA512",
            Self::SHA2_224 => "SHA224",
            Self::SHA3_256 => "SHA3-256",
            Self::SHA3_512 => "SHA3-512",
            Self::Private10 => "Private10",
            Self::Other(v) => return write!(f, "Other({})", v),
            Self::None => "None",
        };
        write!(f, "{}", s)
    }
}

impl zeroize::DefaultIsZeroes for HashAlgorithm {}

/// Trait to work around the fact that the `Digest` trait from rustcrypto can not
/// be used as `Box<Digest>`.
pub trait Hasher: std::io::Write {
    /// Update the hash with the given value.
    fn update(&mut self, _: &[u8]);
    /// Finalize the hash and return the result.
    fn finish(self: Box<Self>) -> Vec<u8>;
    /// Finalize into the provided buffer. Truncates to the length of `out`.
    fn finish_reset_into(&mut self, out: &mut [u8]);
}

macro_rules! derive_hasher {
    ($name:ident, $struct:path) => {
        #[derive(Clone, Default)]
        pub struct $name {
            inner: $struct,
        }

        impl Hasher for $name {
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finish(self: Box<Self>) -> Vec<u8> {
                self.inner.finalize().as_slice().to_vec()
            }

            fn finish_reset_into(&mut self, out: &mut [u8]) {
                let res = self.inner.finalize_reset();
                out.copy_from_slice(&res.as_slice()[..out.len()]);
            }
        }

        impl std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
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
            HashAlgorithm::MD5 => Ok(Box::<Md5Hasher>::default()),
            HashAlgorithm::SHA1 => Ok(Box::<Sha1Hasher>::default()),
            HashAlgorithm::RIPEMD160 => Ok(Box::<Ripemd160Hasher>::default()),
            HashAlgorithm::SHA2_256 => Ok(Box::<Sha2_256Hasher>::default()),
            HashAlgorithm::SHA2_384 => Ok(Box::<Sha2_384Hasher>::default()),
            HashAlgorithm::SHA2_512 => Ok(Box::<Sha2_512Hasher>::default()),
            HashAlgorithm::SHA2_224 => Ok(Box::<Sha2_224Hasher>::default()),
            HashAlgorithm::SHA3_256 => Ok(Box::<Sha3_256Hasher>::default()),
            HashAlgorithm::SHA3_512 => Ok(Box::<Sha3_512Hasher>::default()),
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
            HashAlgorithm::MD5 => Md5::output_size(),
            HashAlgorithm::SHA1 => Sha1::output_size(),
            HashAlgorithm::RIPEMD160 => Ripemd160::output_size(),
            HashAlgorithm::SHA2_256 => sha2::Sha256::output_size(),
            HashAlgorithm::SHA2_384 => sha2::Sha384::output_size(),
            HashAlgorithm::SHA2_512 => sha2::Sha512::output_size(),
            HashAlgorithm::SHA2_224 => sha2::Sha224::output_size(),
            HashAlgorithm::SHA3_256 => sha3::Sha3_256::output_size(),
            HashAlgorithm::SHA3_512 => sha3::Sha3_512::output_size(),
            _ => 0,
        }
    }
}
