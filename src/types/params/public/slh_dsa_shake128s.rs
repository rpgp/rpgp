use std::io::{self, BufRead};

use slh_dsa::Shake128s;

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct SlhDsaShake128sPublicParams {
    #[debug("{}", hex::encode(key.to_bytes()))]
    pub key: slh_dsa::VerifyingKey<Shake128s>,
}

impl Eq for SlhDsaShake128sPublicParams {}

impl SlhDsaShake128sPublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let p = i.read_array::<32>()?;
        let key = slh_dsa::VerifyingKey::try_from(&p[..])?;

        Ok(Self { key })
    }
}

impl Serialize for SlhDsaShake128sPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.key.to_bytes()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for SlhDsaShake128sPublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> SlhDsaShake128sPublicParams {
                let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);

                let key = slh_dsa::SigningKey::new(&mut rng);

                SlhDsaShake128sPublicParams {
                    key: key.as_ref().clone(),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: SlhDsaShake128sPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: SlhDsaShake128sPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = SlhDsaShake128sPublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
