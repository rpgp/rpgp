use std::io::{self, BufRead};

use ml_dsa::MlDsa65;

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

const NISTP384: usize = 97;
const MLDSA65: usize = 1952;

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlDsa65NistP384PublicParams {
    #[debug("{}", hex::encode(nistp384.to_sec1_bytes()))]
    pub nistp384: p384::PublicKey,
    #[debug("{}", hex::encode(ml_dsa.encode()))]
    pub ml_dsa: Box<ml_dsa::VerifyingKey<MlDsa65>>,
}

impl Eq for MlDsa65NistP384PublicParams {}

impl MlDsa65NistP384PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // NIST-P 384 public key
        let p = i.read_arr::<NISTP384>()?;
        let nistp384 = p384::PublicKey::from_sec1_bytes(&p)?;

        // ML DSA key
        let p = i.read_arr_boxed::<MLDSA65>()?;
        let mut boxed = Box::new(ml_dsa::EncodedVerifyingKey::<MlDsa65>::default());
        boxed.copy_from_slice(&p[..]);
        let ml_dsa = ml_dsa::VerifyingKey::decode(&boxed);

        Ok(Self {
            nistp384,
            ml_dsa: Box::new(ml_dsa),
        })
    }
}

impl Serialize for MlDsa65NistP384PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp384.to_sec1_bytes())?;
        writer.write_all(&self.ml_dsa.encode()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NISTP384 + MLDSA65
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::KeyGen;
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlDsa65NistP384PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlDsa65NistP384PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let nistp384 = p384::SecretKey::random(&mut rng).public_key();
                let ml = MlDsa65::key_gen(&mut rng);

                MlDsa65NistP384PublicParams {
                    nistp384,
                    ml_dsa: Box::new(ml.verifying_key().clone()),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlDsa65NistP384PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlDsa65NistP384PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlDsa65NistP384PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
