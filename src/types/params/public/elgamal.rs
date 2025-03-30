use std::io::{self, BufRead};

use crate::{errors::Result, ser::Serialize, types::Mpi};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ElgamalPublicParams {
    p: Mpi,
    g: Mpi,
    y: Mpi,
    #[cfg_attr(test, proptest(value = "false"))]
    encrypt_only: bool,
}

impl ElgamalPublicParams {
    pub(crate) fn is_encrypt_only(&self) -> bool {
        self.encrypt_only
    }

    pub fn try_from_reader<B: BufRead>(mut i: B, encrypt_only: bool) -> Result<Self> {
        // MPI of Elgamal prime p
        let p = Mpi::try_from_reader(&mut i)?;
        // MPI of Elgamal group generator g
        let g = Mpi::try_from_reader(&mut i)?;
        // MPI of Elgamal public key value y (= g**x mod p where x is secret)
        let y = Mpi::try_from_reader(&mut i)?;

        let params = ElgamalPublicParams {
            p,
            g,
            y,
            encrypt_only,
        };

        Ok(params)
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
    use proptest::prelude::*;

    use super::*;

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
            let new_params = ElgamalPublicParams::try_from_reader(&mut &buf[..], false)?;
            prop_assert_eq!(params, new_params);
        }
    }
}
