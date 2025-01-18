//! # Utilities

use std::{hash, io};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::Buf;

use crate::errors::{self, Result};
use crate::parsing::BufParsing;

/// Parse a packet length.
/// <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.7>
pub(crate) fn packet_length_buf<B: Buf>(mut i: B) -> Result<usize> {
    let olen = i.read_u8()?;
    match olen {
        // One-Octet Lengths
        0..=191 => Ok(olen as usize),
        // Two-Octet Lengths
        192..=254 => {
            // subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
            let a = i.read_u8()?;
            let len = ((olen as usize - 192) << 8) + 192 + a as usize;
            Ok(len)
        }
        // Five-Octet Lengths
        255 => {
            // subpacket length = [4-octet scalar starting at 2nd_octet]
            i.read_be_u32().map(|len| len as usize)
        }
    }
}

/// Write packet length, including the prefix for lengths larger or equal than 8384.
pub fn write_packet_length(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 192 {
        writer.write_u8(len.try_into()?)?;
    } else if len < 8384 {
        writer.write_u8((((len - 192) / 256) + 192) as u8)?;
        writer.write_u8(((len - 192) % 256) as u8)?;
    } else {
        writer.write_u8(0xFF)?;
        writer.write_u32::<BigEndian>(len as u32)?;
    }

    Ok(())
}

pub fn write_packet_length_len(len: usize) -> usize {
    if len < 192 {
        1
    } else if len < 8384 {
        2
    } else {
        1 + 4
    }
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

impl<A: hash::Hasher, B: io::Write> io::Write for TeeWriter<'_, A, B> {
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
        write_packet_length(1173, &mut res).unwrap();
        assert_eq!(hex::encode(res), "c3d5");
    }

    #[test]
    fn test_write_packet_length() {
        let mut res = Vec::new();
        write_packet_length(12870, &mut res).unwrap();
        assert_eq!(hex::encode(res), "ff00003246");
    }
}
