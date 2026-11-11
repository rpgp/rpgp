use std::io::{self, BufRead};

use ml_kem::{kem::EncapsulationKey, EncodedSizeUser, MlKem768Params};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

const NIST_P384_PUB_KEY_LENGTH: usize = 97;
const ML_KEM_PUB_KEY_LENGTH: usize = 1184;

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlKem768NistP384PublicParams {
    #[debug("{}", hex::encode(nistp384_key.to_sec1_bytes()))]
    pub nistp384_key: elliptic_curve::PublicKey<p384::NistP384>,
    #[debug("{}", hex::encode(ml_kem_key.as_bytes()))]
    pub ml_kem_key: Box<EncapsulationKey<MlKem768Params>>,
}

impl Eq for MlKem768NistP384PublicParams {}

impl MlKem768NistP384PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // 97 bytes of nistp384 public key
        let nistp384_public_raw = i.read_arr::<NIST_P384_PUB_KEY_LENGTH>()?;

        let ml_kem_raw = i.read_arr::<ML_KEM_PUB_KEY_LENGTH>()?;
        let ml_kem_key = EncapsulationKey::from_bytes(&ml_kem_raw.into());

        Ok(Self {
            nistp384_key: p384::PublicKey::from_sec1_bytes(&nistp384_public_raw)?,
            ml_kem_key: Box::new(ml_kem_key),
        })
    }
}

impl Serialize for MlKem768NistP384PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp384_key.to_sec1_bytes())?;
        writer.write_all(&self.ml_kem_key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NIST_P384_PUB_KEY_LENGTH + ML_KEM_PUB_KEY_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::{KemCore, MlKem768};
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlKem768NistP384PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlKem768NistP384PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let nistp384_key = p384::SecretKey::random(&mut rng).public_key();
                let (_, ml) = MlKem768::generate(&mut rng);

                MlKem768NistP384PublicParams {
                    nistp384_key,
                    ml_kem_key: Box::new(ml),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlKem768NistP384PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlKem768NistP384PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlKem768NistP384PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
