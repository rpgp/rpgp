use errors::Result;
use types::Version;

pub trait Deserialize: Sized {
    fn from_slice(Version, &[u8]) -> Result<Self>;
}
