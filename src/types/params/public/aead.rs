//! Algorithm-Specific Fields for Persistent Symmetric Keys
//!
//! <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-algorithm-specific-fields-f>

use std::{io, io::BufRead};

use byteorder::WriteBytesExt;

use crate::{crypto::sym::SymmetricKeyAlgorithm, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AeadPublicParams {
    pub sym_alg: SymmetricKeyAlgorithm,
    pub seed: [u8; 32],
}

impl AeadPublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> crate::errors::Result<Self> {
        let sym_alg = i.read_u8()?.into();
        let seed = i.read_arr()?;

        let params = AeadPublicParams { sym_alg, seed };
        Ok(params)
    }
}

impl Serialize for AeadPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        writer.write_u8(self.sym_alg.into())?;
        writer.write_all(&self.seed)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        33
    }
}
