/// Parse a user id packet (Tag 13)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.11
pub fn parser(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into()
}
