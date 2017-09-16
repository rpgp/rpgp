use nom::{self, IResult, AsChar, is_alphanumeric};
use std::ops::{Range, RangeFrom, RangeTo};

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
pub fn base64_token<T>(input: T) -> IResult<T, T>
where
    T: nom::Slice<Range<usize>> + nom::Slice<RangeFrom<usize>> + nom::Slice<RangeTo<usize>>,
    T: nom::InputIter + nom::InputLength,
    <T as nom::InputIter>::Item: AsChar,
{
    let input_length = input.input_len();
    if input_length == 0 {
        return IResult::Incomplete(nom::Needed::Unknown);
    }

    for (idx, item) in input.iter_indices() {
        let item = item.as_char();
        if !is_base64_token(item) {
            if idx == 0 {
                return IResult::Error(error_position!(nom::ErrorKind::AlphaNumeric, input));
            } else {
                return IResult::Done(input.slice(idx..), input.slice(0..idx));
            }
        }
    }
    IResult::Done(input.slice(input_length..), input)
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
///    mpi(&[0x00, 0x01, 0x01][..]).unwrap(),
///    (&b""[..], &[1][..])
/// );
///
/// // Decode the number `511` (`0x1FF` in hex).
/// assert_eq!(
///    mpi(&[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
///    (&b""[..], &[0x01, 0xFF][..])
/// );
/// ```
pub fn mpi(input: &[u8]) -> IResult<&[u8], &[u8], u32> {
    mpi_parse(input)
}

named!(mpi_parse<&[u8]>, do_parse!(
       len: u16!(nom::Endianness::Big)
    >> val: take!((len + 7) >> 3)
    >> (val)
));
