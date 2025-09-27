use std::io::{self, BufRead};

use crate::{
    errors::{ensure, Result},
    ser::Serialize,
    types::Mpi,
};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::dsa_pub_gen()"))]
    pub key: dsa::VerifyingKey,
}

// Missing currently, see https://github.com/RustCrypto/signatures/issues/881.
impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    // NIST <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf> (Section 4.2)
    // limits L and N (the bit lengths of p and q, respectively) to 3072/256.
    //
    // However, some OpenPGP keys with 4096 seem to exist in practice, so we allow those.
    const MAX_L_BITS: usize = 4096;
    const MAX_N_BITS: usize = 256;

    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let p = Mpi::try_from_reader(&mut i)?;
        let q = Mpi::try_from_reader(&mut i)?;
        let g = Mpi::try_from_reader(&mut i)?;
        let y = Mpi::try_from_reader(&mut i)?;

        // Cap the lengths of these Mpis to avoid inputs that could cause (slightly)
        // expensive calculations.

        // The prime `p` is limited to L, `q` to N
        ensure!(
            p.len() * 8 <= Self::MAX_L_BITS,
            "p is too long ({} bytes)",
            p.len()
        );
        ensure!(
            q.len() * 8 <= Self::MAX_N_BITS,
            "q is too long ({} bytes)",
            q.len()
        );
        // `g` and `y` are both "mod p", so they are limited to the concrete length of `p`
        ensure!(g.len() <= p.len(), "g is longer than p ({} bytes)", g.len());
        ensure!(y.len() <= p.len(), "y is longer than p ({} bytes)", y.len());

        let params = DsaPublicParams::try_from_mpi(p, q, g, y)?;
        Ok(params)
    }

    pub(crate) fn try_from_mpi(p: Mpi, q: Mpi, g: Mpi, y: Mpi) -> Result<Self> {
        let components = dsa::Components::from_components_unchecked(p.into(), q.into(), g.into())?;
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
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

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
            let new_params = DsaPublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
