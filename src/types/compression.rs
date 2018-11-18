#[derive(Debug, PartialEq, Eq, Clone, FromPrimitive)]
/// Available compression algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.3
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
}
