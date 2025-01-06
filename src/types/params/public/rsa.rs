use std::io;

use num_bigint::BigUint;
use rsa::traits::PublicKeyParts;

use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::{mpi, Mpi, MpiRef};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct RsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::rsa_pub_gen()"))]
    pub key: rsa::RsaPublicKey,
}

impl RsaPublicParams {
    pub fn try_from_slice(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, n) = mpi(i)?;
        let (i, e) = mpi(i)?;

        let params = RsaPublicParams::try_from_mpi(n, e)?;
        Ok((i, params))
    }

    fn try_from_mpi(n: MpiRef<'_>, e: MpiRef<'_>) -> Result<Self> {
        let key = rsa::RsaPublicKey::new_with_max_size(
            BigUint::from_bytes_be(n.as_bytes()),
            BigUint::from_bytes_be(e.as_bytes()),
            crate::crypto::rsa::MAX_KEY_SIZE,
        )?;

        Ok(RsaPublicParams { key })
    }
}

impl From<rsa::RsaPublicKey> for RsaPublicParams {
    fn from(key: rsa::RsaPublicKey) -> Self {
        RsaPublicParams { key }
    }
}
impl Serialize for RsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let n: Mpi = self.key.n().into();
        let e: Mpi = self.key.e().into();

        n.to_writer(writer)?;
        e.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let n: Mpi = self.key.n().into();
        let e: Mpi = self.key.e().into();

        let mut sum = n.write_len();
        sum += e.write_len();
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use rand::SeedableRng;

    prop_compose! {
        pub fn rsa_pub_gen()(seed: u64) -> rsa::RsaPublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            rsa::RsaPrivateKey::new(&mut rng, 512).unwrap().to_public_key()
        }
    }

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: RsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: RsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = RsaPublicParams::try_from_slice(&buf)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}
