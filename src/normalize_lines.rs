//! # Line ending normalization module

use std::sync::LazyLock;

use bytes::{Buf, BufMut, BytesMut};

use crate::{line_writer::LineBreak, util::fill_buffer};

static RE: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"(\r\n|\n)").expect("valid regex"));

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

    /// Fills the buffer, and then normalizes it.
    ///
    /// This is only ever called when `self.replaced` has no more data left to consume.
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        // edge case: if the last byte of the previous read was `\r` and the first of the new read
        // is `\n` we need to make sure to handle it correctly.

        // the previous read was guaranteed to have filled up the buffer (otherwise we would have
        // switched to `self.is_done`, so this is the last byte of the previous read.
        // If this is a CR, it wasn’t handled in the previous call.
        let last_char = self.in_buffer[self.in_buffer.len() - 1];

        let read = fill_buffer(&mut self.source, &mut self.in_buffer, None)?;
        if read < self.in_buffer.len() {
            // When `crate::util::fill_buffer` returns the buffer not fully filled,
            // the underlying reader is guaranteed to be empty -> we're done.
            self.is_done = true;
        }

        self.cleanup_buffer(read, last_char);
        Ok(())
    }

    /// Normalizes the line endings in the current buffer
    fn cleanup_buffer(&mut self, read: usize, last_char: u8) {
        const CR: u8 = b'\r';
        const LF: u8 = b'\n';

        self.replaced.clear();
        let mut start = 0;
        let mut end = read;

        // Did this read fill up `self.in_buffer` and end with a CR?
        if read == self.in_buffer.len() && self.in_buffer[self.in_buffer.len() - 1] == CR {
            // The next boundary could be an edge case, so we are excluding the last byte of this
            // read in this round of processing.
            end = read - 1;
        }

        // Handle edge case where the last byte of the previous buffer was `\r`.
        let edge_case = [last_char, self.in_buffer[0]];
        match (edge_case, read > 0) {
            ([CR, LF], true) => {
                // Edge case, we need to normalize this pair of bytes separately.
                let res = RE.replace_all(&edge_case, self.line_break.as_ref());
                self.replaced.extend_from_slice(&res);

                // We already processed the leading LF in `self.in_buffer`,  so it’s omitted from the final normalization step.
                start = 1;
            }
            ([CR, _], _) => {
                // The last `\r` was not included and normalization is not needed.
                self.replaced.put_u8(CR);
            }
            _ => {}
        }

        // Normalize the remaining part of the buffer ...
        let res = RE.replace_all(&self.in_buffer[start..end], self.line_break.as_ref());
        // ... and copy it into `self.replaced`.
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

    use chacha20::ChaCha8Rng;
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::util::test::{check_strings, random_string, ChaosReader};

    #[test]
    fn reader_normalized_lf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";

        let mut out = String::new();
        NormalizedReader::new(&mut input.as_bytes(), LineBreak::Lf)
            .read_to_string(&mut out)
            .unwrap();

        check_strings(
            out,
            "This is a string \n with \r some \n\n random newlines\r\n\n",
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
            "This is a string \r\n with \r some \r\n\r\n random newlines\r\r\n\r\n",
            out,
        );
    }

    #[test]
    fn reader_normalized_crlf_random() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for _ in 0..100 {
            let size = rng.random_range(1..10000);
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

    #[test]
    fn reader_normalized_crlf_then_lf_edge_case() {
        let input_string = "a \n ".repeat(512);

        let mut out_crlf = String::new();
        NormalizedReader::new(input_string.as_bytes(), LineBreak::Crlf)
            .read_to_string(&mut out_crlf)
            .unwrap();

        let mut reverted = String::new();
        NormalizedReader::new(out_crlf.as_bytes(), LineBreak::Lf)
            .read_to_string(&mut reverted)
            .unwrap();
        check_strings(input_string, reverted);
    }
}
