//! # Utilities

use std::{hash, io};

use digest::DynDigest;
use nom::Input;

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
                       Err($crate::errors::format_err!("invalid packet type: {:?}", other))
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

pub(crate) use impl_try_from_into;

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
        let written = self.b.write(buf)?;
        self.a.write(&buf[..written]);

        Ok(written)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.b.flush()?;

        Ok(())
    }
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
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    #[derive(Debug)]
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
            let to_write: usize = self.rng.random_range(1..=max);

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

#[derive(derive_more::Debug)]
pub struct NormalizingHasher {
    #[debug("hasher")]
    hasher: Box<dyn DynDigest + Send>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn DynDigest + Send>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn DynDigest + Send> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n")
        }

        self.hasher
    }

    pub(crate) fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if !self.text_mode {
            self.hasher.update(buffer);
        } else {
            let mut buf = buffer;

            if self.last_was_cr {
                self.hasher.update(b"\n");

                if buf[0] == b'\n' {
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf.position(|c| c == b'\r' || c == b'\n') {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[]
                    }

                    Some(pos) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                self.hasher.update(b"\r\n");

                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we have normalized it
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        }
    }
}
