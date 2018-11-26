use std::convert::AsMut;
use std::io;
use std::ops::{Range, RangeFrom, RangeTo};

use byteorder::{BigEndian, ByteOrder};
use nom::types::{CompleteByteSlice, CompleteStr};
use nom::{
    self, be_u16, be_u32, be_u8, eol, is_alphanumeric, line_ending, Err, IResult, InputIter,
    InputLength, InputTake, Slice,
};
use num_bigint::BigUint;

use errors;

/// Number of bits we accept when reading or writing MPIs.
/// The value is the same as gnupgs.
const MAX_EXTERN_MPI_BITS: u32 = 16384;

#[inline]
pub fn u8_as_usize(a: u8) -> usize {
    a as usize
}

#[inline]
pub fn u16_as_usize(a: u16) -> usize {
    a as usize
}

#[inline]
pub fn u32_as_usize(a: u32) -> usize {
    a as usize
}

#[inline]
pub fn is_base64_token(c: u8) -> bool {
    is_alphanumeric(c) || c == b'/' || c == b'+' || c == b'=' || c == b'\n' || c == b'\r'
}

named!(pub prefixed<CompleteByteSlice, CompleteByteSlice>, do_parse!(
             many0!(line_ending)
    >> rest: take_while1!(is_base64_token)
    >> (rest)
));

/// Recognizes one or more body tokens
pub fn base64_token(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let input_length = input.input_len();
    if input_length == 0 {
        return Err(Err::Incomplete(nom::Needed::Unknown));
    }

    for (idx, item) in input.iter_indices() {
        if !is_base64_token(item) {
            if idx == 0 {
                return Err(Err::Error(error_position!(
                    input,
                    nom::ErrorKind::AlphaNumeric
                )));
            } else {
                return Ok((input.slice(idx..), input.slice(0..idx)));
            }
        }
    }
    Ok((input.slice(input_length..), input))
}

/// Parse Multi Precision Integers
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-3.2
///
/// # Examples
///
/// ```rust
/// use pgp::util::mpi;
///
/// // Decode the number `1`.
/// assert_eq!(
///     mpi(&[0x00, 0x01, 0x01][..]).unwrap(),
///     (&b""[..], &[1][..])
/// );
/// ```
///
///
pub fn mpi(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let (number, len) = be_u16(input)?;

    let bits = u32::from(len);
    let len_actual = ((bits + 7) >> 3) as u32;

    if len_actual > MAX_EXTERN_MPI_BITS {
        Err(Err::Error(error_position!(
            input,
            nom::ErrorKind::Custom(errors::MPI_TOO_LONG)
        )))
    } else {
        // same as take!
        let cnt = len_actual as usize;
        match number.slice_index(cnt) {
            None => nom::need_more(number, nom::Needed::Size(cnt)),
            Some(index) => Ok(number.take_split(index)),
        }
    }
}

/// Convert a BigUint to an MPI for use in packets.
pub fn bignum_to_mpi(n: &BigUint) -> Vec<u8> {
    let number = n.to_bytes_be();
    let mut res = vec![0u8; number.len() + 2];
    BigEndian::write_uint(&mut res[0..2], n.bits() as u64, 2);
    res[2..].copy_from_slice(&number[..]);
    res
}

/// Returns the bit length of a given slice.
pub fn bit_size(val: &[u8]) -> usize {
    (val.len() * 8) - val[0].leading_zeros() as usize
}

pub fn write_mpi(val: &[u8], w: &mut impl io::Write) -> errors::Result<()> {
    let size = bit_size(val);

    w.write_all(&[(size >> 8) as u8, size as u8])?;
    w.write_all(val)?;

    Ok(())
}

/// Parse an mpi and convert it to a `BigUint`.
named!(pub mpi_big<BigUint>, map!(mpi, BigUint::from_bytes_be));

/// Convert a slice into an array
pub fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

#[rustfmt::skip]
named!(pub packet_length<usize>, do_parse!(
       olen: be_u8
    >>  len: switch!(value!(olen),
                     // One-Octet Lengths
                     0...191   => value!(olen as usize) |
                     // Two-Octet Lengths
                     192...254 => map!(be_u8, |a| {
                         ((olen as usize - 192) << 8) + 192 + a as usize
                     }) |
                     // Five-Octet Lengths
                     255       => map!(be_u32, u32_as_usize)
    )
    >> (len)
));

pub fn end_of_line(input: CompleteStr) -> IResult<CompleteStr, CompleteStr> {
    alt!(input, eof!() | eol)
}

/// Return the length of the remaining input.
// Adapted from https://github.com/Geal/nom/pull/684
#[inline]
pub fn rest_len<T>(input: T) -> IResult<T, usize>
where
    T: Slice<Range<usize>> + Slice<RangeFrom<usize>> + Slice<RangeTo<usize>>,
    T: InputLength,
{
    let len = input.input_len();
    Ok((input, len))
}

#[macro_export]
macro_rules! impl_try_from_into {
    ($enum_name:ident, $( $name:ident => $variant_type:ty ),*) => {
       $(
           impl $crate::try_from::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Err = $crate::errors::Error;

               fn try_from(other: $enum_name) -> ::std::result::Result<$variant_type, Self::Err> {
                   if let $enum_name::$name(value) = other {
                       Ok(value)
                   } else {
                      Err(format_err!("invalid packet type: {:?}", other))
                   }
               }
           }

           impl From<$variant_type> for $enum_name {
               fn from(other: $variant_type) -> $enum_name {
                   $enum_name::$name(other)
               }
           }
       )*
    }
}

pub fn read_string_lossy(raw: &[u8]) -> String {
    // first try utf8
    match ::std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // now try chars
            // this might be lossy, that is okay
            raw.iter().map(|c| *c as char).collect::<String>()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpi() {
        // Decode the number `511` (`0x1FF` in hex).
        assert_eq!(
            mpi(&[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
            (&b""[..], &[0x01, 0xFF][..])
        );

        // Decode the number `2^255 + 7`.
        assert_eq!(
            mpi(&[
                0x01, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x07
            ][..])
            .unwrap(),
            (
                &b""[..],
                &[
                    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0x07
                ][..]
            )
        );
    }

    #[test]
    fn test_read_string_lossy() {
        assert_eq!(read_string_lossy(b"hello"), "hello".to_string());
        assert_eq!(
            read_string_lossy(&[
                74, 252, 114, 103, 101, 110, 32, 77, 97, 114, 115, 99, 104, 97, 108, 108, 32, 60,
                106, 117, 101, 114, 103, 101, 110, 46, 109, 97, 114, 115, 99, 104, 97, 108, 108,
                64, 112, 114, 111, 109, 112, 116, 46, 100, 101, 62
            ]),
            "Jürgen Marschall <juergen.marschall@prompt.de>".to_string()
        );
    }
}
