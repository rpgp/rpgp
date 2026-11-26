//! CRC24 checksum of the optional ASCII Armor checksum line.
//!
//! <https://www.rfc-editor.org/rfc/rfc9580.html#name-optional-checksum>

use std::hash::Hasher;

static CRC24: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_24_OPENPGP);

/// Incremental CRC24 over the (unarmored) data.
#[derive(Clone)]
pub(crate) struct Crc24Hasher(crc::Digest<'static, u32>);

impl Crc24Hasher {
    pub(crate) fn new() -> Self {
        Self(CRC24.digest())
    }
}

impl Default for Crc24Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Crc24Hasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(&self) -> u64 {
        u64::from(self.0.clone().finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc24(chunks: &[&[u8]]) -> u64 {
        let mut hasher = Crc24Hasher::new();
        for chunk in chunks {
            hasher.write(chunk);
        }
        hasher.finish()
    }

    #[test]
    fn test_crc24() {
        // initial value, RFC 9580 section 6.1.1
        assert_eq!(crc24(&[]), 0xb704ce);
        // check value of CRC-24/OPENPGP
        assert_eq!(crc24(&[b"123456789"]), 0x21cf02);
        // incremental updates give the same result
        assert_eq!(crc24(&[b"1234", b"", b"56789"]), 0x21cf02);
    }
}
