use std::io;

use nom::be_u8;
use num_traits::FromPrimitive;

use crypto::hash::HashAlgorithm;
use errors::Result;
use ser::Serialize;

const EXPBIAS: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringToKey {
    pub typ: StringToKeyType,
    pub hash: HashAlgorithm,
    pub salt: Option<Vec<u8>>,
    pub count: Option<u8>,
}

impl StringToKey {
    /// Converts a coded count into the count.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-3.7.1.3
    pub fn count(&self) -> Option<usize> {
        match self.count {
            Some(c) => {
                Some(((16u32 + u32::from(c & 15)) << (u32::from(c >> 4) + EXPBIAS)) as usize)
            }
            None => None,
        }
    }
}

/// Available String-To-Key types
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
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
    match typ {
        StringToKeyType::Salted | StringToKeyType::IteratedAndSalted => true,
        _ => false,
    }
}

/// Has the given s2k type a count?
fn has_count(typ: StringToKeyType) -> bool {
    match typ {
        StringToKeyType::IteratedAndSalted => true,
        _ => false,
    }
}

#[rustfmt::skip]
named!(pub s2k_parser<StringToKey>, do_parse!(
         typ: map_opt!(be_u8, StringToKeyType::from_u8)
    >>  hash: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>  salt: cond!(has_salt(typ), map!(take!(8), |v| v.to_vec()))
    >> count: cond!(has_count(typ), be_u8)
    >> (StringToKey {
        typ,
        hash,
        salt,
        count,
    })
));

impl Serialize for StringToKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.typ as u8, self.hash as u8])?;

        if let Some(ref salt) = self.salt {
            writer.write_all(salt)?;
        }

        if let Some(count) = self.count {
            writer.write_all(&[count])?;
        }

        Ok(())
    }
}
