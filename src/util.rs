//! # Utilities

use std::ops::{Range, RangeFrom, RangeTo};
use std::{hash, io};

use byteorder::{BigEndian, WriteBytesExt};
use nom::branch::alt;
use nom::bytes::streaming::take_while1;
use nom::character::is_alphanumeric;
use nom::character::streaming::line_ending;
use nom::combinator::{eof, map};
use nom::multi::many0;
use nom::number::streaming::{be_u32, be_u8};
use nom::sequence::preceded;
use nom::{error_position, Err, InputIter, InputLength, Slice};

use crate::errors::{self, IResult};

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

pub fn prefixed(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(many0(line_ending), take_while1(is_base64_token))(input)
}

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
                    nom::error::ErrorKind::AlphaNumeric
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
    bytes
        .iter()
        .position(|b| b != &0)
        .map_or(&[], |offset| &bytes[offset..])
}

#[inline]
pub fn strip_leading_zeros_vec(bytes: &mut Vec<u8>) {
    if let Some(offset) = bytes.iter_mut().position(|b| b != &0) {
        bytes.drain(..offset);
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
pub(crate) fn packet_length(i: &[u8]) -> IResult<&[u8], usize> {
    let (i, olen) = be_u8(i)?;
    match olen {
        // One-Octet Lengths
        0..=191 => Ok((i, olen as usize)),
        // Two-Octet Lengths
        192..=254 => map(be_u8, |a| ((olen as usize - 192) << 8) + 192 + a as usize)(i),
        // Five-Octet Lengths
        255 => map(be_u32, u32_as_usize)(i),
    }
}

/// Write packet length, including the prefix.
pub fn write_packet_length(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 8384 {
        // nothing
    } else {
        writer.write_u8(0xFF)?;
    }

    write_packet_len(len, writer)
}

/// Write the raw packet length.
pub fn write_packet_len(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 192 {
        writer.write_u8(len.try_into()?)?;
    } else if len < 8384 {
        writer.write_u8((((len - 192) / 256) + 192) as u8)?;
        writer.write_u8(((len - 192) % 256) as u8)?;
    } else {
        writer.write_u32::<BigEndian>(len as u32)?;
    }

    Ok(())
}

pub fn end_of_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((eof, end_of_line))(input)
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
           impl std::convert::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Error = $crate::errors::Error;

               fn try_from(other: $enum_name) -> ::std::result::Result<$variant_type, Self::Error> {
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
    #![allow(clippy::unwrap_used)]

    use super::*;

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

    #[test]
    fn test_strip_leading_zeros_with_all_zeros() {
        let buf = [0, 0, 0];
        let stripped = strip_leading_zeros(&buf);
        assert_eq!(stripped, &[]);
    }

    #[test]
    fn test_strip_leading_zeros_vec() {
        let mut vec = vec![0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        strip_leading_zeros_vec(&mut vec);
        assert_eq!(vec, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
