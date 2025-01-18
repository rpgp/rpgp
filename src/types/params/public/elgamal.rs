use std::io;

use bytes::Buf;

use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::MpiBytes;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ElgamalPublicParams {
    p: MpiBytes,
    g: MpiBytes,
    y: MpiBytes,
}

impl ElgamalPublicParams {
    pub fn try_from_buf<B: Buf>(mut i: B) -> Result<Self> {
        // MPI of Elgamal prime p
        let p = MpiBytes::from_buf(&mut i)?;
        // MPI of Elgamal group generator g
        let g = MpiBytes::from_buf(&mut i)?;
        // MPI of Elgamal public key value y (= g**x mod p where x is secret)
        let y = MpiBytes::from_buf(&mut i)?;

        let params = ElgamalPublicParams { p, g, y };

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
            let new_params = ElgamalPublicParams::try_from_buf(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
