use std::io::{self, BufRead};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

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
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // 32 bytes of public key
        let p = i.read_array::<32>()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&p)?;
        let params = Self { key };

        Ok(params)
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
    use proptest::prelude::*;

    use super::*;

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
            let new_params = Ed25519PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
