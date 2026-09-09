use std::io::{self, BufRead};

use ml_dsa::MlDsa87;

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

const NISTP521: usize = 133;
const MLDSA87: usize = 2592;

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlDsa87NistP521PublicParams {
    #[debug("{}", hex::encode(nistp521.to_sec1_bytes()))]
    pub nistp521: p521::PublicKey,
    #[debug("{}", hex::encode(ml_dsa.encode()))]
    pub ml_dsa: Box<ml_dsa::VerifyingKey<MlDsa87>>,
}

impl Eq for MlDsa87NistP521PublicParams {}

impl MlDsa87NistP521PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // NIST-P 521 public key
        let p = i.read_arr::<NISTP521>()?;
        let nistp521 = p521::PublicKey::from_sec1_bytes(&p)?;

        // ML DSA key
        let p = i.read_arr_boxed::<MLDSA87>()?;
        let mut boxed = Box::new(ml_dsa::EncodedVerifyingKey::<MlDsa87>::default());
        boxed.copy_from_slice(&p[..]);
        let ml_dsa = ml_dsa::VerifyingKey::decode(&boxed);

        Ok(Self {
            nistp521,
            ml_dsa: Box::new(ml_dsa),
        })
    }
}

impl Serialize for MlDsa87NistP521PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp521.to_sec1_bytes())?;
        writer.write_all(&self.ml_dsa.encode()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NISTP521 + MLDSA87
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::KeyGen;
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlDsa87NistP521PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlDsa87NistP521PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let nistp521 = p521::SecretKey::random(&mut rng).public_key();
                let ml = MlDsa87::key_gen(&mut rng);

                MlDsa87NistP521PublicParams {
                    nistp521,
                    ml_dsa: Box::new(ml.verifying_key().clone()),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlDsa87NistP521PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlDsa87NistP521PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlDsa87NistP521PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
