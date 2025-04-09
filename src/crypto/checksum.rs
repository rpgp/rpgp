use std::{hash::Hasher, io};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(display(
    "checksum mismatch 0x{} != 0x{}",
    hex::encode(expected),
    hex::encode(actual)
))]
pub struct ChecksumMismatch {
    expected: [u8; 2],
    actual: [u8; 2],
}

/// Two octet checksum: sum of all octets mod 65535.
#[inline]
pub fn simple(actual: [u8; 2], data: &[u8]) -> Result<(), ChecksumMismatch> {
    // Then a two-octet checksum is appended, which is equal to the
    // sum of the preceding session key octets, not including the algorithm
    // identifier, modulo 65536.
    let expected_checksum = calculate_simple(data);
    let expected = expected_checksum.to_be_bytes();

    if actual != expected {
        return Err(ChecksumMismatchSnafu { actual, expected }.build());
    }

    Ok(())
}

pub fn simple_to_writer<W: io::Write>(data: &[u8], writer: &mut W) -> io::Result<()> {
    let mut hasher = SimpleChecksum::default();
    hasher.write(data);
    hasher.to_writer(writer)
}

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

#[derive(Debug, Snafu)]
#[snafu(display("SHA1 hash collision occurred"), visibility(pub(super)))]
pub struct Sha1HashCollision;

/// SHA1 checksum, using sha1_checked, first 20 octets.
///
/// Fails with `Error::HashCollision` if a SHA1 collision was detected.
pub fn calculate_sha1<I, T>(data: I) -> Result<[u8; 20], Sha1HashCollision>
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
            Err(Sha1HashCollisionSnafu {}.build())
        }
    }
}
