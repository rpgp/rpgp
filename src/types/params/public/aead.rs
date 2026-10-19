//! Algorithm-Specific Fields for Persistent Symmetric Keys
//!
//! <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html#name-algorithm-specific-fields-f>

use std::{io, io::BufRead};

use byteorder::WriteBytesExt;

use crate::{crypto::sym::SymmetricKeyAlgorithm, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct AeadPublicParams {
    pub sym_alg: SymmetricKeyAlgorithm,
    pub fingerprint_seed: [u8; 32],
}

impl AeadPublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> crate::errors::Result<Self> {
        let sym_alg = i.read_u8()?.into();
        let fingerprint_seed = i.read_arr()?;

        Ok(AeadPublicParams {
            sym_alg,
            fingerprint_seed,
        })
    }
}

impl Serialize for AeadPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        writer.write_u8(self.sym_alg.into())?;
        writer.write_all(&self.fingerprint_seed)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        33
    }
}
