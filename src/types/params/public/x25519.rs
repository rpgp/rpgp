use std::io::{self, BufRead};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct X25519PublicParams {
    #[cfg_attr(test, proptest(strategy = "super::ecdh::tests::ecdh_curve25519_gen()"))]
    pub key: x25519_dalek::PublicKey,
}

impl X25519PublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x>
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // 32 bytes of public key
        let public_raw = i.read_array::<32>()?;
        let public = x25519_dalek::PublicKey::from(public_raw);
        let params = Self { key: public };

        Ok(params)
    }
}

impl Serialize for X25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: X25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: X25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = X25519PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
