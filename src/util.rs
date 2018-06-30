use nom::types::CompleteStr;
use nom::{
    self, be_u16, be_u32, be_u8, eol, is_alphanumeric, AsChar, Err, IResult, InputIter, InputTake,
};
use std::convert::AsMut;
use std::ops::{Range, RangeFrom, RangeTo};
use std::str;

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

pub fn collect_into_string(vec: Vec<&[u8]>) -> String {
    vec.iter()
        .map(|s| str::from_utf8(s).unwrap())
        .collect::<Vec<&str>>()
        .join("")
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
///
/// // Decode the number `511` (`0x1FF` in hex).
/// assert_eq!(
///     mpi(&[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
///     (&b""[..], &[0x01, 0xFF][..])
/// );
///
/// // Decode the number `2^255 + 7`.
/// assert_eq!(
///     mpi(&[0x01, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07][..]).unwrap(),
///     (&b""[..], &[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07][..])
/// );
/// ```
///
///
pub fn mpi(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let len = be_u16(&input[0..2]);

    match len {
        Ok((_, len)) => {
            let len_actual = ((len + 7) >> 3) as u32 + 2;
            if len_actual > MAX_EXTERN_MPI_BITS {
                Err(Err::Error(error_position!(
                    input,
                    nom::ErrorKind::Custom(errors::MPI_TOO_LONG)
                )))
            } else {
                // same as take!
                let cnt = len_actual as usize;
                match input.slice_index(cnt) {
                    None => nom::need_more(input, nom::Needed::Size(cnt)),
                    Some(index) => Ok(input.take_split(index)),
                }
            }
        }
        Err(err) => Err(err),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_collect_into_string() {
        assert_eq!(
            collect_into_string(vec![b"hello", b" ", b"world"]),
            "hello world"
        );
    }
}
