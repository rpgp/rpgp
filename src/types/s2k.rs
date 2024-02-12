use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{cond, map};
use nom::number::streaming::be_u8;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};

use crate::crypto::hash::HashAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;

const EXPBIAS: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringToKey {
    typ: StringToKeyType,
    hash: HashAlgorithm,
    salt: Option<Vec<u8>>,
    count: Option<u8>,
}

impl StringToKey {
    pub fn new_default<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        StringToKey::new_iterated(rng, HashAlgorithm::default(), 224)
    }

    pub fn new_iterated<R: CryptoRng + Rng>(rng: &mut R, hash: HashAlgorithm, count: u8) -> Self {
        let mut salt = vec![0u8; 8];
        rng.fill(&mut salt[..]);

        StringToKey {
            typ: StringToKeyType::IteratedAndSalted,
            hash,
            salt: Some(salt),
            count: Some(count),
        }
    }
}

impl StringToKey {
    /// Converts a coded count into the count.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-3.7.1.3
    pub fn count(&self) -> Option<usize> {
        match self.count {
            Some(c) => {
                let res = ((16u32 + u32::from(c & 15)) << (u32::from(c >> 4) + EXPBIAS)) as usize;
                Some(res)
            }
            None => None,
        }
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_ref().map(|salt| &salt[..])
    }

    pub fn hash(&self) -> HashAlgorithm {
        self.hash
    }

    pub fn typ(&self) -> StringToKeyType {
        self.typ
    }

    /// String-To-Key methods are used to convert a given password string into a key.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-3.7
    pub fn derive_key(&self, passphrase: &str, key_size: usize) -> Result<Vec<u8>> {
        let digest_size = self.hash.digest_size();
        let rounds = (key_size as f32 / digest_size as f32).ceil() as usize;

        let mut key = Vec::with_capacity(key_size);

        for round in 0..rounds {
            let mut hasher = self.hash.new_hasher()?;

            // add 0s prefix
            if round > 0 {
                hasher.update(&vec![0u8; round][..]);
            }

            match self.typ {
                StringToKeyType::Simple => {
                    hasher.update(passphrase.as_bytes());
                }
                StringToKeyType::Salted => {
                    hasher.update(self.salt.as_ref().expect("missing salt"));
                    hasher.update(passphrase.as_bytes());
                }
                StringToKeyType::IteratedAndSalted => {
                    let salt = self.salt.as_ref().expect("missing salt");
                    let pw = passphrase.as_bytes();
                    let data_size = salt.len() + pw.len();
                    // how many bytes are supposed to be hashed
                    let mut count = self.count().expect("missing count");

                    if count < data_size {
                        // if the count is less, hash one full set
                        count = data_size;
                    }

                    while count > data_size {
                        hasher.update(salt);
                        hasher.update(pw);
                        count -= data_size;
                    }

                    if count < salt.len() {
                        hasher.update(&salt[..count]);
                    } else {
                        hasher.update(salt);
                        count -= salt.len();
                        hasher.update(&pw[..count]);
                    }
                }
                _ => unimplemented_err!("S2K {:?} is not available", self.typ),
            }

            if key_size - key.len() < digest_size {
                let end = key_size - key.len();
                key.extend_from_slice(&hasher.finish()[..end]);
            } else {
                key.extend_from_slice(&hasher.finish()[..]);
            }
        }

        Ok(key)
    }
}

/// Available String-To-Key types
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum StringToKeyType {
    Simple = 0,
    Salted = 1,
    Reserved = 2,
    IteratedAndSalted = 3,

    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Default for StringToKeyType {
    fn default() -> Self {
        Self::IteratedAndSalted
    }
}

impl StringToKeyType {
    pub fn param_len(self) -> usize {
        match self {
            // 1 octet hash algorithm.
            StringToKeyType::Simple => 1,
            // Salted has 1 octet hash algorithm and 8 octets salt value.
            StringToKeyType::Salted => 9,
            // Salted and iterated has 1 octet hash algorithm, 8 octets salt value and 1 octet count.
            StringToKeyType::IteratedAndSalted => 10,
            _ => 0,
        }
    }
}

/// Has the given s2k type a salt?
fn has_salt(typ: StringToKeyType) -> bool {
    matches!(
        typ,
        StringToKeyType::Salted | StringToKeyType::IteratedAndSalted
    )
}

/// Has the given s2k type a count?
fn has_count(typ: StringToKeyType) -> bool {
    matches!(typ, StringToKeyType::IteratedAndSalted)
}

pub fn s2k_parser(i: &[u8]) -> IResult<&[u8], StringToKey> {
    let (i, typ) = map(be_u8, StringToKeyType::from)(i)?;
    let (i, hash) = map(be_u8, HashAlgorithm::from)(i)?;
    let (i, salt) = cond(has_salt(typ), map(take(8usize), |v: &[u8]| v.to_vec()))(i)?;
    let (i, count) = cond(has_count(typ), be_u8)(i)?;
    Ok((
        i,
        StringToKey {
            typ,
            hash,
            salt,
            count,
        },
    ))
}

impl Serialize for StringToKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[u8::from(self.typ), u8::from(self.hash)])?;

        if let Some(ref salt) = self.salt {
            writer.write_all(salt)?;
        }

        if let Some(count) = self.count {
            writer.write_all(&[count])?;
        }

        Ok(())
    }
}
