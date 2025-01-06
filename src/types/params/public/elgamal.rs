use std::io;

use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::{mpi, Mpi};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ElgamalPublicParams {
    p: Mpi,
    g: Mpi,
    y: Mpi,
}

impl ElgamalPublicParams {
    pub fn try_from_slice(i: &[u8]) -> IResult<&[u8], Self> {
        // MPI of Elgamal prime p
        let (i, p) = mpi(i)?;
        // MPI of Elgamal group generator g
        let (i, g) = mpi(i)?;
        // MPI of Elgamal public key value y (= g**x mod p where x is secret)
        let (i, y) = mpi(i)?;

        let params = ElgamalPublicParams {
            p: p.to_owned(),
            g: g.to_owned(),
            y: y.to_owned(),
        };

        Ok((i, params))
    }
}

impl Serialize for ElgamalPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.p.to_writer(writer)?;
        self.g.to_writer(writer)?;
        self.y.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        sum += self.p.write_len();
        sum += self.g.write_len();
        sum += self.y.write_len();
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: ElgamalPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: ElgamalPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = ElgamalPublicParams::try_from_slice(&buf)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}
