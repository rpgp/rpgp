use std::io;

use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::dsa_pub_gen()"))]
    pub key: dsa::VerifyingKey,
}

// Missing currently, see https://github.com/RustCrypto/signatures/issues/881.
impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    pub fn try_from_mpi(
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
    use rand::SeedableRng;

    proptest::prop_compose! {
        pub fn dsa_pub_gen()(seed: u64) -> dsa::VerifyingKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let components = dsa::Components::generate(&mut rng, dsa::KeySize::DSA_2048_256);
            let signing_key = dsa::SigningKey::generate(&mut rng, components);
            signing_key.verifying_key().clone()
        }
    }
}
