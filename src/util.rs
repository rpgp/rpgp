//! # Utilities

use std::{hash, io};

pub(crate) fn fill_buffer<R: std::io::Read>(
    mut source: R,
    buffer: &mut [u8],
    chunk_size: Option<usize>,
) -> std::io::Result<usize> {
    let mut offset = 0;
    let chunk_size = chunk_size.unwrap_or(buffer.len());
    loop {
        let read = source.read(&mut buffer[offset..chunk_size])?;
        offset += read;

        if read == 0 || offset == chunk_size {
            break;
        }
    }
    Ok(offset)
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
pub(crate) mod test {
    use bytes::{Buf, Bytes};
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~\r\n .,-!?\t";

    pub(crate) fn random_string(rng: &mut impl Rng, size: usize) -> String {
        (0..size)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    pub(crate) struct ChaosReader<R: Rng> {
        rng: R,
        source: Bytes,
    }

    impl<R: Rng> ChaosReader<R> {
        pub(crate) fn new(rng: R, source: impl Into<Bytes>) -> Self {
            Self {
                rng,
                source: source.into(),
            }
        }
    }

    impl<R: Rng> std::io::Read for ChaosReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.source.has_remaining() {
                return Ok(0);
            }
            let max = buf.len().min(self.source.remaining());
            let to_write: usize = self.rng.gen_range(1..=max);

            self.source.copy_to_slice(&mut buf[..to_write]);
            Ok(to_write)
        }
    }

    pub(crate) fn check_strings(a: impl AsRef<str>, b: impl AsRef<str>) {
        assert_eq!(
            escape_string::escape(a.as_ref()),
            escape_string::escape(b.as_ref())
        );
    }
}
