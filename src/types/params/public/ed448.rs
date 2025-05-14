use std::io::{self, BufRead};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Ed448PublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::ed448_pub_gen()"))]
    pub key: ed448_goldilocks::VerifyingKey,
}

impl Ed448PublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed4>
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // 57 bytes of public key
        let p = i.read_array::<57>()?;
        let key = ed448_goldilocks::VerifyingKey::from_bytes(&p)?;
        let params = Self { key };

        Ok(params)
    }
}

impl Serialize for Ed448PublicParams {
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

    proptest::prop_compose! {
        pub fn ed448_pub_gen()(bytes: [u8; 57]) -> ed448_goldilocks::VerifyingKey {
            let secret = ed448_goldilocks::SigningKey::from(ed448_goldilocks::EdwardsScalarBytes::clone_from_slice(&bytes));
            secret.verifying_key()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: Ed448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: Ed448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = Ed448PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
