use std::io::{self, BufRead};

use ml_dsa::MlDsa87;

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlDsa87Ed448PublicParams {
    #[debug("{}", hex::encode(ed448.as_bytes()))]
    pub ed448: ed448_goldilocks::VerifyingKey,
    #[debug("{}", hex::encode(ml_dsa.encode()))]
    pub ml_dsa: Box<ml_dsa::VerifyingKey<MlDsa87>>,
}

impl Eq for MlDsa87Ed448PublicParams {}

impl MlDsa87Ed448PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // ed448 public key
        let p = i.read_array::<57>()?;
        let ed448 = ed448_goldilocks::VerifyingKey::from_bytes(&p)?;

        // ML DSA key
        let p = i.read_array::<2592>()?;
        let ml_dsa = ml_dsa::VerifyingKey::decode(&(p.into()));

        Ok(Self {
            ed448,
            ml_dsa: Box::new(ml_dsa),
        })
    }
}

impl Serialize for MlDsa87Ed448PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.ed448.as_bytes()[..])?;
        writer.write_all(&self.ml_dsa.encode()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        57 + 2592
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::KeyGen;
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlDsa87Ed448PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlDsa87Ed448PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let x = ed448_goldilocks::SigningKey::generate(&mut rng);
                let ml = MlDsa87::key_gen(&mut rng);

                MlDsa87Ed448PublicParams {
                    ed448: x.verifying_key(),
                    ml_dsa: Box::new(ml.verifying_key().clone()),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlDsa87Ed448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlDsa87Ed448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlDsa87Ed448PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
