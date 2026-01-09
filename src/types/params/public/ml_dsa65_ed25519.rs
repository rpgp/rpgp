use std::io::{self, BufRead};

use ml_dsa::MlDsa65;

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlDsa65Ed25519PublicParams {
    #[debug("{}", hex::encode(ed25519.as_bytes()))]
    pub ed25519: ed25519_dalek::VerifyingKey,
    #[debug("{}", hex::encode(ml_dsa.encode()))]
    pub ml_dsa: Box<ml_dsa::VerifyingKey<MlDsa65>>,
}

impl Eq for MlDsa65Ed25519PublicParams {}

impl MlDsa65Ed25519PublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2>
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // ed25519 public key
        let p = i.read_array::<32>()?;
        let ed25519 = ed25519_dalek::VerifyingKey::from_bytes(&p)?;

        // ML DSA key
        let p = i.read_array_boxed::<1952>()?;
        let mut boxed = Box::new(ml_dsa::EncodedVerifyingKey::<MlDsa65>::default());
        boxed.copy_from_slice(&p[..]);
        let ml_dsa = ml_dsa::VerifyingKey::decode(&boxed);

        Ok(Self {
            ed25519,
            ml_dsa: Box::new(ml_dsa),
        })
    }
}

impl Serialize for MlDsa65Ed25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.ed25519.as_bytes()[..])?;
        writer.write_all(&self.ml_dsa.encode()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        32 + 1952
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::KeyGen;
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlDsa65Ed25519PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlDsa65Ed25519PublicParams {
                let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);

                let x = ed25519_dalek::SigningKey::generate(&mut rng);
                let ml = MlDsa65::key_gen(&mut rng);

                MlDsa65Ed25519PublicParams {
                    ed25519: x.verifying_key(),
                    ml_dsa: Box::new(ml.verifying_key().clone()),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlDsa65Ed25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlDsa65Ed25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlDsa65Ed25519PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
