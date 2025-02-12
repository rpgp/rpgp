//! # Line ending normalization module
//!
//! This crate provides a `normalize` method that takes an u8 iterator and returns
//! a new one with newlines normalized to a single style.
//!
//! Based on <https://github.com/derekdreery/normalize-line-endings>.

use std::iter::Peekable;
use std::sync::LazyLock;

use bytes::{Buf, BytesMut};

use crate::line_writer::LineBreak;
use crate::util::fill_buffer;

/// This struct wraps an u8 iterator to normalize line endings.
pub struct Normalized<I>
where
    I: Iterator<Item = u8>,
{
    line_break: LineBreak,
    iter: Peekable<I>,
    prev_was_cr: bool,
}

impl<I: Iterator<Item = u8>> Normalized<I> {
    /// Take a u8 iterator and return similar iterator with normalized line endings
    ///
    /// # Example
    /// ```
    /// use std::iter::FromIterator;
    ///
    /// use pgp::line_writer::LineBreak;
    /// use pgp::normalize_lines::Normalized;
    ///
    /// let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
    /// assert_eq!(
    ///     &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Lf).collect()).unwrap(),
    ///     "This is a string \n with \n some \n\n random newlines\n\n\n"
    /// );
    /// ```
    pub fn new(iter: I, line_break: LineBreak) -> Normalized<I> {
        Normalized {
            iter: iter.peekable(),
            prev_was_cr: false,
            line_break,
        }
    }
}

impl<I: Iterator<Item = u8>> Iterator for Normalized<I> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        match self.iter.peek() {
            Some(b'\n') => {
                match self.line_break {
                    LineBreak::Lf => {
                        if self.prev_was_cr {
                            // we already inserted a \n
                            let _ = self.iter.next();
                        }

                        self.iter.next()
                    }
                    LineBreak::Cr => {
                        // skip \n
                        let _ = self.iter.next();

                        if self.prev_was_cr {
                            self.prev_was_cr = false;
                            self.next()
                        } else {
                            Some(b'\r')
                        }
                    }
                    LineBreak::Crlf => {
                        if self.prev_was_cr {
                            self.prev_was_cr = false;
                            self.iter.next()
                        } else {
                            self.prev_was_cr = true;
                            Some(b'\r')
                        }
                    }
                }
            }
            Some(b'\r') => match self.line_break {
                LineBreak::Lf => {
                    self.prev_was_cr = true;
                    let _ = self.iter.next();
                    Some(b'\n')
                }
                LineBreak::Cr => {
                    self.prev_was_cr = true;
                    self.iter.next()
                }
                LineBreak::Crlf => {
                    if self.prev_was_cr {
                        self.prev_was_cr = false;
                        Some(b'\n')
                    } else {
                        self.prev_was_cr = true;
                        self.iter.next()
                    }
                }
            },
            _ => match self.line_break {
                LineBreak::Lf | LineBreak::Cr => {
                    self.prev_was_cr = false;
                    self.iter.next()
                }
                LineBreak::Crlf => {
                    let res = if self.prev_was_cr {
                        Some(b'\n')
                    } else {
                        self.iter.next()
                    };
                    self.prev_was_cr = false;
                    res
                }
            },
        }
    }
}

static RE: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"(\r\n?|\n)").expect("valid regex"));

/// This struct wraps a reader and normalize line endings.
pub struct NormalizedReader<R>
where
    R: std::io::Read,
{
    line_break: LineBreak,
    source: R,
    in_buffer: [u8; BUF_SIZE / 2],
    replaced: BytesMut,
    is_done: bool,
}

const BUF_SIZE: usize = 1024;
impl<R: std::io::Read> NormalizedReader<R> {
    pub fn new(source: R, line_break: LineBreak) -> Self {
        Self {
            source,
            line_break,
            in_buffer: [0u8; BUF_SIZE / 2],
            replaced: BytesMut::with_capacity(BUF_SIZE),
            is_done: false,
        }
    }

    /// Fills the buffer, and then normalizes it
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        // edge case, if the last byte of the previous buffer was `\r` and the first of the new is `\n`
        // we need to make sure to correctly handle it.
        let last_was_cr = self.in_buffer[self.in_buffer.len() - 1] == b'\r';
        let read = fill_buffer(&mut self.source, &mut self.in_buffer, None)?;
        if read == 0 {
            self.is_done = true;
        }
        let first_is_lf = self.in_buffer[0] == b'\n';

        self.cleanup_buffer(read, last_was_cr && first_is_lf);

        Ok(())
    }

    /// Normalizes the line endings in the current buffer
    fn cleanup_buffer(&mut self, read: usize, have_split_crlf: bool) {
        let in_buffer = if have_split_crlf {
            // skip the first byte of the buffer, which is a `\n` as it was already handled before
            &self.in_buffer[1..read]
        } else {
            &self.in_buffer[..read]
        };

        let res = RE.replace_all(in_buffer, self.line_break.as_ref());
        self.replaced.clear();
        self.replaced.extend_from_slice(&res);
    }
}

impl<R: std::io::Read> std::io::Read for NormalizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.replaced.has_remaining() {
            if self.is_done {
                return Ok(0);
            }
            self.fill_buffer()?;
        }

        let to_write = self.replaced.remaining().min(buf.len());
        self.replaced.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

#[cfg(test)]
pub(crate) fn normalize_lines(s: &str, line_break: LineBreak) -> std::borrow::Cow<'_, str> {
    let bytes = RE.replace_all(s.as_bytes(), line_break.as_ref());
    match bytes {
        std::borrow::Cow::Borrowed(bytes) => {
            std::borrow::Cow::Borrowed(std::str::from_utf8(bytes).expect("valid bytes in"))
        }
        std::borrow::Cow::Owned(bytes) => {
            std::borrow::Cow::Owned(std::string::String::from_utf8(bytes).expect("valid bytes in"))
        }
    }
}

// tests
#[cfg(test)]
mod tests {
    use std::io::Read;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::util::test::{check_strings, random_string, ChaosReader};

    use super::*;

    #[test]
    fn normalized_lf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Lf).collect()).unwrap(),
            "This is a string \n with \n some \n\n random newlines\n\n\n"
        );
    }

    #[test]
    fn normalized_cr() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Cr).collect()).unwrap(),
            "This is a string \r with \r some \r\r random newlines\r\r\r"
        );
    }

    #[test]
    fn normalized_crlf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Crlf).collect()).unwrap(),
            "This is a string \r\n with \r\n some \r\n\r\n random newlines\r\n\r\n\r\n"
        );
    }

    #[test]
    fn reader_normalized_lf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";

        let mut out = String::new();
        NormalizedReader::new(&mut input.as_bytes(), LineBreak::Lf)
            .read_to_string(&mut out)
            .unwrap();

        check_strings(
            out,
            "This is a string \n with \n some \n\n random newlines\n\n\n",
        );
    }

    #[test]
    fn reader_normalized_cr() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";

        let mut out = String::new();
        NormalizedReader::new(&mut input.as_bytes(), LineBreak::Cr)
            .read_to_string(&mut out)
            .unwrap();

        check_strings(
            out,
            "This is a string \r with \r some \r\r random newlines\r\r\r",
        );
    }

    #[test]
    fn reader_normalized_crlf_fixed() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";

        let mut out = String::new();
        NormalizedReader::new(&mut input.as_bytes(), LineBreak::Crlf)
            .read_to_string(&mut out)
            .unwrap();

        check_strings(
            "This is a string \r\n with \r\n some \r\n\r\n random newlines\r\n\r\n\r\n",
            out,
        );
    }

    #[test]
    fn reader_normalized_crlf_random() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for _ in 0..100 {
            let size = rng.gen_range(1..10000);
            let input = random_string(&mut rng, size);
            let reader = ChaosReader::new(&mut rng, input.clone());

            let mut out = String::new();
            NormalizedReader::new(reader, LineBreak::Crlf)
                .read_to_string(&mut out)
                .unwrap();

            let normalized_input = normalize_lines(&input, LineBreak::Crlf);
            check_strings(&normalized_input, out);
        }
    }
}
