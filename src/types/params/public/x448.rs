use std::io::{self, BufRead};

use crate::{
    errors::{format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct X448PublicParams {
    pub key: x448::PublicKey,
}

impl X448PublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4>
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let key = i.read_array::<56>()?;

        let params = X448PublicParams {
            key: x448::PublicKey::from_bytes(&key)
                .ok_or_else(|| format_err!("invalid x448 public key"))?,
        };

        Ok(params)
    }
}

impl Serialize for X448PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        56
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for X448PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> X448PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let secret = x448::Secret::new(&mut rng);
                X448PublicParams {
                    key: (&secret).into(),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

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
            let new_params = X448PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
