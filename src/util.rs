//! # Utilities

use std::{hash, io};

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
