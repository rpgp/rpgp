use std::io;

use bytes::Buf;

use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::MpiBytes;

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::dsa_pub_gen()"))]
    pub key: dsa::VerifyingKey,
}

// Missing currently, see https://github.com/RustCrypto/signatures/issues/881.
impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    pub fn try_from_buf<B: Buf>(mut i: B) -> Result<Self> {
        let p = MpiBytes::from_buf(&mut i)?;
        let q = MpiBytes::from_buf(&mut i)?;
        let g = MpiBytes::from_buf(&mut i)?;
        let y = MpiBytes::from_buf(&mut i)?;

        let params = DsaPublicParams::try_from_mpi(p, q, g, y)?;
        Ok(params)
    }

    pub(crate) fn try_from_mpi(p: MpiBytes, q: MpiBytes, g: MpiBytes, y: MpiBytes) -> Result<Self> {
        let components = dsa::Components::from_components(p.into(), q.into(), g.into())?;
        let key = dsa::VerifyingKey::from_components(components, y.into())?;

        Ok(DsaPublicParams { key })
    }
}

impl Serialize for DsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let c = self.key.components();
        let p: MpiBytes = c.p().into();
        p.to_writer(writer)?;
        let q: MpiBytes = c.q().into();
        q.to_writer(writer)?;
        let g: MpiBytes = c.g().into();
        g.to_writer(writer)?;
        let y: MpiBytes = self.key.y().into();
        y.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;

        let c = self.key.components();
        let p: MpiBytes = c.p().into();
        sum += p.write_len();
        let q: MpiBytes = c.q().into();
        sum += q.write_len();
        let g: MpiBytes = c.g().into();
        sum += g.write_len();
        let y: MpiBytes = self.key.y().into();
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
            let new_params = DsaPublicParams::try_from_buf(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
