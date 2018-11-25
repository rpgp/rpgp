use errors::Result;

pub trait Deserialize: Sized {
    fn from_slice(&[u8]) -> Result<Self>;
}
