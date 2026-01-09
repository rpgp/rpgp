use std::io::{self, BufRead};

use ml_kem::{kem::EncapsulationKey, EncodedSizeUser, MlKem768Params};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

const ML_KEM_PUB_KEY_LENGTH: usize = 1184;

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct MlKem768X25519PublicParams {
    #[debug("{}", hex::encode(x25519_key.as_bytes()))]
    pub x25519_key: x25519_dalek::PublicKey,
    #[debug("{}", hex::encode(ml_kem_key.as_bytes()))]
    pub ml_kem_key: Box<EncapsulationKey<MlKem768Params>>,
}

impl Eq for MlKem768X25519PublicParams {}

impl MlKem768X25519PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        // 32 bytes of x25519 public key
        let x25519_public_raw = i.read_array::<32>()?;

        let ml_kem_raw = i.read_array::<ML_KEM_PUB_KEY_LENGTH>()?;
        let ml_kem_key = EncapsulationKey::from_bytes(&ml_kem_raw.into());

        Ok(Self {
            x25519_key: x25519_dalek::PublicKey::from(x25519_public_raw),
            ml_kem_key: Box::new(ml_kem_key),
        })
    }
}

impl Serialize for MlKem768X25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.x25519_key.as_bytes())?;
        writer.write_all(&self.ml_kem_key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        32 + ML_KEM_PUB_KEY_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::{KemCore, MlKem768};
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;
    use crate::crypto::ecc_curve::ECCCurve;

    impl Arbitrary for MlKem768X25519PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlKem768X25519PublicParams {
                let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
                let mut secret_key_bytes = [0u8; ECCCurve::Curve25519.secret_key_length()];
                rng.fill_bytes(&mut secret_key_bytes);

                let secret = x25519_dalek::StaticSecret::from(secret_key_bytes);
                let x = x25519_dalek::PublicKey::from(&secret);
                let (_, ml) = MlKem768::generate(&mut rng);

                MlKem768X25519PublicParams {
                    x25519_key: x,
                    ml_kem_key: Box::new(ml),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlKem768X25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlKem768X25519PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlKem768X25519PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
