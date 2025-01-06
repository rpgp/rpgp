use std::io;

use num_bigint::BigUint;
use rsa::traits::PublicKeyParts;

use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct RsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::rsa_pub_gen()"))]
    pub key: rsa::RsaPublicKey,
}

impl RsaPublicParams {
    pub fn try_from_mpi(n: MpiRef<'_>, e: MpiRef<'_>) -> Result<Self> {
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
    use rand::SeedableRng;

    proptest::prop_compose! {
        pub fn rsa_pub_gen()(seed: u64) -> rsa::RsaPublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap().to_public_key()
        }
    }
}
