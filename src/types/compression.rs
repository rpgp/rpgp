use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
/// Available compression algorithms.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-compression-algorithms>
#[repr(u8)]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
    /// Do not use, just for compatibility with GnuPG.
    Private10 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}
