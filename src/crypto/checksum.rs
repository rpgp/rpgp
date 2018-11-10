use byteorder::{BigEndian, ReadBytesExt};
use sha1::{Digest, Sha1};

use errors::Result;

/// Two octet checksum: sum of all octets mod 65535.
#[inline]
pub fn simple(actual: &[u8], data: &[u8]) -> Result<()> {
    // Then a two-octet checksum is appended, which is equal to the
    // sum of the preceding session key octets, not including the algorithm
    // identifier, modulo 65536.
    let mut actual = actual;
    let checksum = u32::from(actual.read_u16::<BigEndian>()?);
    let expected_checksum = data.iter().map(|v| u32::from(*v)).sum::<u32>() & 0xffff;

    ensure_eq!(checksum, expected_checksum, "invalid simple checksum");

    Ok(())
}

/// SHA1 checksum, first 20 octets.
#[inline]
pub fn sha1(hash: &[u8], data: &[u8]) -> Result<()> {
    ensure_eq!(hash, &Sha1::digest(data)[0..20], "invalid SHA1 checksum");

    Ok(())
}
