use crate::errors::Result;
use crate::types::Version;

pub trait Deserialize: Sized {
    fn from_slice(_: Version, _: &[u8]) -> Result<Self>;
}
