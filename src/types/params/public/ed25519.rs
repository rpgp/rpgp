use std::io;

use nom::bytes::complete::take;

use crate::errors::{IResult, Result};
use crate::ser::Serialize;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Ed25519PublicParams {
    #[cfg_attr(
        test,
        proptest(strategy = "super::eddsa_legacy::tests::ed25519_pub_gen()")
    )]
    pub key: ed25519_dalek::VerifyingKey,
}

impl Ed25519PublicParams {
    /// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2
    pub fn try_from_slice(i: &[u8]) -> IResult<&[u8], Self> {
        // 32 bytes of public key
        let (i, p) = take(32u8)(i)?;
        let key = p.try_into().expect("we took 32 bytes");
        let params = Self { key };

        Ok((i, params))
    }
}

impl Serialize for Ed25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.key.as_bytes()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.as_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn params_write_len(params: Ed25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: Ed25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = Ed25519PublicParams::try_from_slice(&buf)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}
