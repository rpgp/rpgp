use errors::Result;
use types::SecretKeyRepr;

pub trait SecretKeyTrait {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>;
}

impl<'a, T: SecretKeyTrait> SecretKeyTrait for &'a T {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        (*self).unlock(pw, work)
    }
}
