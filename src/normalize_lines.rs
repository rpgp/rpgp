//! # Line ending normalization module

use std::sync::LazyLock;

use bytes::{Buf, BytesMut};

use crate::{line_writer::LineBreak, util::fill_buffer};

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
        let in_buffer = if have_split_crlf && read > 0 {
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
}
