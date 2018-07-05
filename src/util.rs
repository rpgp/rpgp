use nom::types::CompleteStr;
use nom::{
    self, be_u16, be_u32, be_u8, eol, is_alphanumeric, AsChar, Err, IResult, InputIter,
    InputLength, InputTake, Slice,
};
use openssl::bn::BigNum;
use std::convert::AsMut;
use std::ops::{Range, RangeFrom, RangeTo};

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
pub fn is_base64_token(c: char) -> bool {
    is_alphanumeric(c as u8) || c == '/' || c == '+'
}

/// Recognizes one or more body tokens
pub fn base64_token<T>(input: T) -> nom::IResult<T, T>
where
    T: nom::Slice<Range<usize>> + nom::Slice<RangeFrom<usize>> + nom::Slice<RangeTo<usize>>,
    T: nom::InputIter + nom::InputLength,
    <T as nom::InputIter>::Item: AsChar,
{
    let input_length = input.input_len();
    if input_length == 0 {
        return Err(Err::Incomplete(nom::Needed::Unknown));
    }

    for (idx, item) in input.iter_indices() {
        let item = item.as_char();
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

    let len_actual = (u32::from(len) + 7) >> 3;

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

/// Parse an mpi and convert it to a `BigNum`.
named!(pub mpi_big<BigNum>, map_res!(mpi, BigNum::from_slice));

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
}
