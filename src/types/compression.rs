use num_enum::{FromPrimitive, IntoPrimitive};

/// Available compression algorithms.
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-compression-algorithms>
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[non_exhaustive]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
    /// Do not use, just for compatibility with GnuPG.
    #[cfg_attr(test, proptest(skip))] // not supported
    Private10 = 110,

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))] // not supported
    Other(u8),
}
