use std::io::{self, BufRead};

use ml_kem::{kem::EncapsulationKey, EncodedSizeUser, MlKem1024Params};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

const NIST_P521_PUB_KEY_LENGTH: usize = 133;
const ML_KEM_PUB_KEY_LENGTH: usize = 1568;

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlKem1024NistP521PublicParams {
    #[debug("{}", hex::encode(nistp521_key.to_sec1_bytes()))]
    pub nistp521_key: elliptic_curve::PublicKey<p521::NistP521>,
    #[debug("{}", hex::encode(ml_kem_key.as_bytes()))]
    pub ml_kem_key: Box<EncapsulationKey<MlKem1024Params>>,
}

impl Eq for MlKem1024NistP521PublicParams {}

impl MlKem1024NistP521PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let nistp521_public_raw = i.read_arr::<NIST_P521_PUB_KEY_LENGTH>()?;
        let nistp521_key = p521::PublicKey::from_sec1_bytes(&nistp521_public_raw)?;

        let ml_kem_raw = i.read_arr::<ML_KEM_PUB_KEY_LENGTH>()?;
        let ml_kem_key = EncapsulationKey::from_bytes(&ml_kem_raw.into());

        Ok(Self {
            nistp521_key,
            ml_kem_key: Box::new(ml_kem_key),
        })
    }
}

impl Serialize for MlKem1024NistP521PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp521_key.to_sec1_bytes())?;
        writer.write_all(&self.ml_kem_key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NIST_P521_PUB_KEY_LENGTH + ML_KEM_PUB_KEY_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::{KemCore, MlKem1024};
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlKem1024NistP521PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlKem1024NistP521PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let nistp521_key = p521::SecretKey::random(&mut rng).public_key();
                let (_, ml) = MlKem1024::generate(&mut rng);

                MlKem1024NistP521PublicParams {
                    nistp521_key,
                    ml_kem_key: Box::new(ml),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlKem1024NistP521PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlKem1024NistP521PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlKem1024NistP521PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
