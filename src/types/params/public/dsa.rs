use std::io;

use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::{mpi, Mpi, MpiRef};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::dsa_pub_gen()"))]
    pub key: dsa::VerifyingKey,
}

// Missing currently, see https://github.com/RustCrypto/signatures/issues/881.
impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    pub fn try_from_slice(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, p) = mpi(i)?;
        let (i, q) = mpi(i)?;
        let (i, g) = mpi(i)?;
        let (i, y) = mpi(i)?;

        let params = DsaPublicParams::try_from_mpi(p, q, g, y)?;
        Ok((i, params))
    }

    pub(crate) fn try_from_mpi(
        p: MpiRef<'_>,
        q: MpiRef<'_>,
        g: MpiRef<'_>,
        y: MpiRef<'_>,
    ) -> Result<Self> {
        let components = dsa::Components::from_components(p.into(), q.into(), g.into())?;
        let key = dsa::VerifyingKey::from_components(components, y.into())?;

        Ok(DsaPublicParams { key })
    }
}

impl Serialize for DsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let c = self.key.components();
        let p: Mpi = c.p().into();
        p.to_writer(writer)?;
        let q: Mpi = c.q().into();
        q.to_writer(writer)?;
        let g: Mpi = c.g().into();
        g.to_writer(writer)?;
        let y: Mpi = self.key.y().into();
        y.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;

        let c = self.key.components();
        let p: Mpi = c.p().into();
        sum += p.write_len();
        let q: Mpi = c.q().into();
        sum += q.write_len();
        let g: Mpi = c.g().into();
        sum += g.write_len();
        let y: Mpi = self.key.y().into();
        sum += y.write_len();
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;

    use proptest::prelude::*;

    prop_compose! {
        pub fn dsa_pub_gen()(seed: u64) -> dsa::VerifyingKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            #[allow(deprecated)]
            let components = dsa::Components::generate(&mut rng, dsa::KeySize::DSA_1024_160);
            let signing_key = dsa::SigningKey::generate(&mut rng, components);
            signing_key.verifying_key().clone()
        }
    }

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len(params: DsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(params: DsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = DsaPublicParams::try_from_slice(&buf)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}
