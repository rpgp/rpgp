use std::convert::AsMut;
use std::ops::{Range, RangeFrom, RangeTo};
use std::{hash, io};

use buf_redux::{BufReader, Buffer};
use byteorder::{BigEndian, WriteBytesExt};
use nom::types::{CompleteByteSlice, CompleteStr};
use nom::{
    self, be_u32, be_u8, eol, is_alphanumeric, line_ending, Err, IResult, InputIter, InputLength,
    Slice,
};

use crate::errors;

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

named!(pub prefixed<CompleteByteSlice<'_>, CompleteByteSlice<'_>>, do_parse!(
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

/// Returns the bit length of a given slice.
#[inline]
pub fn bit_size(val: &[u8]) -> usize {
    if val.is_empty() {
        0
    } else {
        (val.len() * 8) - val[0].leading_zeros() as usize
    }
}

#[inline]
pub fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    if let Some(offset) = bytes.iter().position(|b| b != &0) {
        &bytes[offset..]
    } else {
        bytes
    }
}

#[inline]
pub fn strip_leading_zeros_vec(bytes: &mut Vec<u8>) {
    if let Some(offset) = bytes.iter_mut().position(|b| b != &0) {
        for i in 0..offset {
            bytes.remove(i);
        }
    }
}

/// Convert a slice into an array.
pub fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

// Parse a packet length.
#[rustfmt::skip]
named!(pub packet_length<usize>, do_parse!(
       olen: be_u8
    >>  len: switch!(value!(olen),
                     // One-Octet Lengths
                     0..=191   => value!(olen as usize) |
                     // Two-Octet Lengths
                     192..=254 => map!(be_u8, |a| {
                         ((olen as usize - 192) << 8) + 192 + a as usize
                     }) |
                     // Five-Octet Lengths
                     255       => map!(be_u32, u32_as_usize)
    )
    >> (len)
));

/// Write packet length, including the prefix.
pub fn write_packet_length(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 8384 {
        // nothing
    } else {
        writer.write_all(&[0xFF])?;
    }

    write_packet_len(len, writer)
}

/// Write the raw packet length.
pub fn write_packet_len(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 192 {
        writer.write_all(&[len as u8])?;
    } else if len < 8384 {
        writer.write_all(&[(((len - 192) / 256) + 192) as u8, ((len - 192) % 256) as u8])?;
    } else {
        writer.write_u32::<BigEndian>(len as u32)?;
    }

    Ok(())
}

pub fn end_of_line(input: CompleteStr<'_>) -> IResult<CompleteStr<'_>, CompleteStr<'_>> {
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
           impl try_from::TryFrom<$enum_name> for $variant_type {
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

pub fn write_string(val: &str) -> Vec<u8> {
    val.chars().map(|c| c as u8).collect()
}

pub fn read_string(raw: &[u8]) -> String {
    raw.iter().map(|c| *c as char).collect::<String>()
}

pub struct TeeWriter<'a, A, B> {
    a: &'a mut A,
    b: &'a mut B,
}

impl<'a, A, B> TeeWriter<'a, A, B> {
    pub fn new(a: &'a mut A, b: &'a mut B) -> Self {
        TeeWriter { a, b }
    }
}

impl<'a, A: hash::Hasher, B: io::Write> io::Write for TeeWriter<'a, A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.a.write(buf);
        write_all(&mut self.b, buf)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.b.flush()?;

        Ok(())
    }
}

#[cfg(feature = "ringbuf")]
#[inline(always)]
pub fn new_buffer(capacity: usize) -> Buffer {
    Buffer::with_capacity_ringbuf(capacity)
}

#[cfg(not(feature = "ringbuf"))]
#[inline(always)]
pub fn new_buffer(capacity: usize) -> Buffer {
    Buffer::with_capacity(capacity)
}

#[cfg(feature = "ringbuf")]
#[inline(always)]
pub fn new_buf_reader<R>(capacity: usize, inner: R) -> BufReader<R> {
    BufReader::with_capacity_ringbuf(capacity, inner)
}

#[cfg(not(feature = "ringbuf"))]
#[inline(always)]
pub fn new_buf_reader<R>(capacity: usize, inner: R) -> BufReader<R> {
    BufReader::with_capacity(capacity, inner)
}

/// The same as the std lib, but doesn't choke on write 0. This is a hack, to be compatible with
/// rust-base64.
pub fn write_all(writer: &mut impl io::Write, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match writer.write(buf) {
            Ok(0) => {}
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_string() {
        assert_eq!(read_string(b"hello"), "hello".to_string());
        assert_eq!(
            read_string(&[
                74, 252, 114, 103, 101, 110, 32, 77, 97, 114, 115, 99, 104, 97, 108, 108, 32, 60,
                106, 117, 101, 114, 103, 101, 110, 46, 109, 97, 114, 115, 99, 104, 97, 108, 108,
                64, 112, 114, 111, 109, 112, 116, 46, 100, 101, 62
            ]),
            "Jürgen Marschall <juergen.marschall@prompt.de>".to_string()
        );
    }

    #[test]
    fn test_write_string() {
        let vals = vec![
            vec![
                74, 252, 114, 103, 101, 110, 32, 77, 97, 114, 115, 99, 104, 97, 108, 108, 32, 60,
                106, 117, 101, 114, 103, 101, 110, 46, 109, 97, 114, 115, 99, 104, 97, 108, 108,
                64, 112, 114, 111, 109, 112, 116, 46, 100, 101, 62,
            ],
            hex::decode("4275527354664c6f3064203c73616d75656c2e726f7474406f72616e67652e66723e")
                .unwrap(),
        ];

        for val in &vals {
            assert_eq!(&write_string(&read_string(val)), val);
        }
    }

    #[test]
    fn test_write_packet_len() {
        let mut res = Vec::new();
        write_packet_len(1173, &mut res).unwrap();
        assert_eq!(hex::encode(res), "c3d5");
    }

    #[test]
    fn test_write_packet_length() {
        let mut res = Vec::new();
        write_packet_length(12870, &mut res).unwrap();
        assert_eq!(hex::encode(res), "ff00003246");
    }
}
