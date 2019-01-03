use crypto::hash::HashAlgorithm;
use errors::Result;
use types::{PublicKeyTrait, SecretKeyRepr};

pub trait SecretKeyTrait: PublicKeyTrait {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>;

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>>
    where
        F: FnOnce() -> String;
}

impl<'a, T: SecretKeyTrait> SecretKeyTrait for &'a T {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        (*self).unlock(pw, work)
    }

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>>
    where
        F: FnOnce() -> String,
    {
        (*self).create_signature(key_pw, hash, data)
    }
}
