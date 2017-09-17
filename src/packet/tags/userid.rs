use std::str;

/// Parse a user id packet (Tag 13)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.11
pub fn parser<'a>(raw: &'a [u8]) -> Result<&'a str, str::Utf8Error> {
    str::from_utf8(raw)
}
