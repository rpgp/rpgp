//! Deserialize trait

use crate::errors::Result;
use crate::packet::Span;
use crate::types::Version;

pub trait Deserialize: Sized {
    fn from_slice(_: Version, _: Span<'_>) -> Result<Self>;
}
