//! Persistent Symmetric Key support
//!
//! <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-algorithm-specific-fields-f>

use bytes::Bytes;
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{aead::AeadAlgorithm, sym::SymmetricKeyAlgorithm, Decryptor},
    errors::Result,
    ser::Serialize,
    types::Tag,
};

/// Secret key for AEAD persistent symmetric keys
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    pub(crate) key: Vec<u8>, // sized to match the sym_alg in the public key part
}

pub struct EncryptionFields<'a> {
    pub data: &'a Bytes,
    pub aead: AeadAlgorithm,
    pub version: u8,
    pub sym_alg: SymmetricKeyAlgorithm,
    pub salt: &'a [u8; 32],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        let info = (
            Tag::PublicKeyEncryptedSessionKey, // FIXME: does this need to be flexible?
            data.version,
            data.aead,
            data.sym_alg,
        );

        let (key, iv) = crate::packet::symmetric::derive(&self.key, data.salt, info);

        let mut buf = data.data.clone().into(); // FIXME: don't clone

        data.aead
            .decrypt_in_place(&data.sym_alg, &key, &iv, &[], &mut buf)?;

        Ok(buf.into())
    }
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
