use std::io;

use nom::bytes::streaming::take;

use crate::errors::{IResult, Result};
use crate::ser::Serialize;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct X448PublicParams {
    pub key: [u8; 56],
}

impl X448PublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4>
    pub fn try_from_slice(i: &[u8]) -> IResult<&[u8], Self> {
        // 56 bytes of public key
        let (i, p) = take(56u8)(i)?;
        let params = X448PublicParams {
            key: p.try_into().expect("we took 56 bytes"),
        };

        Ok((i, params))
    }
}

impl Serialize for X448PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.key.as_ref())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: X448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: X448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = X448PublicParams::try_from_slice(&buf)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}
