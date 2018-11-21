use errors::Result;
use types::SecretKeyRepr;

pub trait SecretKeyTrait {
    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>;
}
