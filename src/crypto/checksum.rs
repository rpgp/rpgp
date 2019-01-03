use byteorder::{BigEndian, WriteBytesExt};
use sha1::{Digest, Sha1};

use errors::Result;

/// Two octet checksum: sum of all octets mod 65535.
#[inline]
pub fn simple(actual: &[u8], data: &[u8]) -> Result<()> {
    // Then a two-octet checksum is appended, which is equal to the
    // sum of the preceding session key octets, not including the algorithm
    // identifier, modulo 65536.
    let expected_checksum = calculate_simple(data);

    ensure_eq!(
        &actual[..2],
        &expected_checksum[..],
        "invalid simple checksum"
    );

    Ok(())
}

/// SHA1 checksum, first 20 octets.
#[inline]
pub fn sha1(hash: &[u8], data: &[u8]) -> Result<()> {
    ensure_eq!(hash, &Sha1::digest(data)[0..20], "invalid SHA1 checksum");

    Ok(())
}

#[inline]
pub fn calculate_simple(data: &[u8]) -> Vec<u8> {
    let val = (data.iter().map(|v| u32::from(*v)).sum::<u32>() & 0xffff) as u16;
    let mut res = Vec::with_capacity(2);
    res.write_u16::<BigEndian>(val).expect("pre allocated");

    res
}
