//! Persistent Symmetric Key support
//!
//! <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-algorithm-specific-fields-f>

use zeroize::ZeroizeOnDrop;

use crate::{errors::Result, ser::Serialize};

/// Secret key for AEAD persistent symmetric keys
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    pub(crate) key: Vec<u8>, // sized to match the sym_alg in the public key part
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.key)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.len()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    prop_compose! {
        pub fn key_gen()(seed: u64) -> Vec<u8> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let mut key   = vec![0u8 ;32]; // FIXME: size depends on sym alg!

            rng.fill(&mut key[..]);

            key
        }
    }
}
