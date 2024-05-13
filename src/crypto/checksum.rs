use std::hash::Hasher;
use std::io;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use crate::errors::Result;

/// Two octet checksum: sum of all octets mod 65535.
#[inline]
pub fn simple(actual: &[u8], data: &[u8]) -> Result<()> {
    // Then a two-octet checksum is appended, which is equal to the
    // sum of the preceding session key octets, not including the algorithm
    // identifier, modulo 65536.
    let expected_checksum = calculate_simple(data);

    ensure_eq!(
        &actual[..2],
        &expected_checksum.to_be_bytes()[..],
        "invalid simple checksum"
    );

    Ok(())
}

#[inline]
pub fn simple_to_writer<W: io::Write>(data: &[u8], writer: &mut W) -> io::Result<()> {
    let mut hasher = SimpleChecksum::default();
    hasher.write(data);
    hasher.to_writer(writer)
}

#[inline]
pub fn calculate_simple(data: &[u8]) -> u16 {
    let mut hasher = SimpleChecksum::default();
    hasher.write(data);
    hasher.finish() as u16
}

#[derive(Debug, Default)]
pub struct SimpleChecksum(u16);

impl SimpleChecksum {
    #[inline]
    pub fn to_writer<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u16::<BigEndian>(self.0)
    }

    #[inline]
    pub fn finalize(&self) -> [u8; 2] {
        let mut res = [0u8; 2];
        BigEndian::write_u16(&mut res[..], self.0);

        res
    }
}

impl io::Write for SimpleChecksum {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Hasher::write(self, buf);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Hasher for SimpleChecksum {
    #[inline]
    fn write(&mut self, buf: &[u8]) {
        let new_sum = buf.iter().map(|v| u32::from(*v)).sum::<u32>();
        self.0 = ((u32::from(self.0) + new_sum) & 0xffff) as u16;
    }

    #[inline]
    fn finish(&self) -> u64 {
        u64::from(self.0)
    }
}

/// SHA1 checksum, using sha1_checked, first 20 octets.
///
/// Fails with `Error::HashCollision` if a SHA1 collision was detected.
#[inline]
pub fn calculate_sha1<I, T>(data: I) -> Result<[u8; 20]>
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item = T>,
{
    use sha1_checked::{CollisionResult, Digest, Sha1};

    let mut digest = Sha1::new();
    for chunk in data {
        digest.update(chunk.as_ref());
    }

    match digest.try_finalize() {
        CollisionResult::Ok(sha1) => Ok(sha1.into()),
        CollisionResult::Collision(_) | CollisionResult::Mitigated(_) => {
            Err(crate::errors::Error::Sha1HashCollision)
        }
    }
}
