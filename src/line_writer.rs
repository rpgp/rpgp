use std::io;

use buf_redux::Buffer;
use generic_array::{ArrayLength, GenericArray};

const CRLF: [u8; 2] = [b'\r', b'\n'];
const CR: [u8; 1] = [b'\r'];
const LF: [u8; 1] = [b'\n'];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LineBreak {
    Crlf,
    Lf,
    Cr,
}

impl AsRef<[u8]> for LineBreak {
    fn as_ref(&self) -> &[u8] {
        match self {
            LineBreak::Crlf => &CRLF[..],
            LineBreak::Lf => &LF[..],
            LineBreak::Cr => &CR[..],
        }
    }
}

/// A `Write` implementation that splits any written bytes into the given length lines.
///
///
/// # Panics
///
/// Calling `write()` after `finish()` is invalid and will panic.
pub struct LineWriter<'a, W: 'a + io::Write, N: ArrayLength<u8>> {
    /// Which kind of line break to inser.
    line_break: LineBreak,
    /// Where encoded data is written to.
    w: &'a mut W,
    /// Holds a partial chunk, if any, after the last `write()`, so that we may then fill the chunk
    /// with the next `write()`, write it, then proceed with the rest of the input normally.
    extra: GenericArray<u8, N>,
    /// How much of `extra` is occupied, in `[0, N]`.
    extra_len: usize,
    buffer: Buffer,
    /// True iff partial last chunk has been written.
    finished: bool,
    /// panic safety: don't write again in destructor if writer panicked while we were writing to it
    panicked: bool,
}

impl<'a, W: io::Write, N: ArrayLength<u8>> LineWriter<'a, W, N> {
    /// Create a new encoder around an existing writer.
    pub fn new(w: &'a mut W, line_break: LineBreak) -> Self {
        LineWriter {
            line_break,
            w,
            extra: Default::default(),
            buffer: Buffer::with_capacity(1024),
            extra_len: 0,
            finished: false,
            panicked: false,
        }
    }

    /// Wrie all remaining buffered data.
    ///
    /// Once this succeeds, no further writes can be performed.
    ///
    /// # Errors
    ///
    /// Assuming the wrapped writer obeys the `Write` contract, if this returns `Err`, no data was
    /// written, and `finish()` may be retried if appropriate for the type of error, etc.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        };

        if self.extra_len > 0 {
            self.panicked = true;
            let _ = self.w.write(&self.extra[..self.extra_len])?;
            self.panicked = false;
            // write succeeded, do not write the encoding of extra again if finish() is retried
            self.extra_len = 0;
        }

        self.finished = true;
        Ok(())
    }
}

impl<'a, W: io::Write, N: ArrayLength<u8>> io::Write for LineWriter<'a, W, N> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.finished {
            panic!("Cannot write more after calling finish()");
        }

        if input.is_empty() {
            return Ok(0);
        }

        // The contract of `Write::write` places some constraints on this implementation:
        // - a call to `write()` represents at most one call to a wrapped `Write`, so we can't
        // iterate over the input and encode multiple chunks.
        // - Errors mean that "no bytes were written to this writer", so we need to reset the
        // internal state to what it was before the error occurred

        let sl = N::to_usize();
        let line_break = self.line_break.as_ref();

        let orig_extra_len = self.extra_len;

        // process leftover stuff from last write
        if self.extra_len + input.len() < sl {
            // still not enough
            self.extra_len += input.len();
            self.extra[orig_extra_len..self.extra_len].copy_from_slice(input);
            Ok(input.len())
        } else {
            let mut buffer_pos = 0;
            let mut input_pos = 0;

            if self.extra_len > 0 {
                self.buffer.copy_from_slice(&self.extra[..orig_extra_len]);
                buffer_pos += orig_extra_len;
            }

            if buffer_pos % sl != 0 {
                let missing = sl - (buffer_pos % sl);

                self.buffer
                    .copy_from_slice(&input[input_pos..input_pos + missing]);

                buffer_pos += missing;
                input_pos += missing;

                // insert line break
                self.buffer.copy_from_slice(line_break);

                buffer_pos += line_break.len();
            }

            while (input.len() - input_pos) >= sl {
                let missing = sl;
                self.buffer
                    .copy_from_slice(&input[input_pos..input_pos + missing]);

                buffer_pos += missing;
                input_pos += missing;

                // insert line break
                self.buffer.copy_from_slice(line_break);

                buffer_pos += line_break.len();
            }

            // last one gets stored
            let rest_len = input.len() - input_pos;
            self.extra[0..rest_len].copy_from_slice(&input[input_pos..]);
            self.extra_len = rest_len;

            self.panicked = true;
            let r = self.buffer.write_to(self.w);
            self.panicked = false;

            self.buffer.consume(buffer_pos);

            match r {
                Ok(_) => Ok(input.len()),
                Err(_) => {
                    // in case we filled and encoded `extra`, reset extra_len
                    self.extra_len = orig_extra_len;
                    r
                }
            }
        }
    }

    /// Because this is usually treated as OK to call multiple times, it will *not* flush any
    /// incomplete chunks of input or write padding.
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<'a, W: io::Write, N: ArrayLength<u8>> Drop for LineWriter<'a, W, N> {
    fn drop(&mut self) {
        if !self.panicked {
            // like `BufWriter`, ignore errors during drop
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{self, U10};
    use std::io::Write;

    #[test]
    fn simple_writes() {
        let mut buf = Vec::new();

        {
            let mut w = LineWriter::<_, U10>::new(&mut buf, LineBreak::Crlf);

            // short write
            assert_eq!(w.write(&[0, 1, 2, 3]).unwrap(), 4);
            assert_eq!(w.write(&[4, 5, 6, 7]).unwrap(), 4);
            assert_eq!(w.write(&[8, 9, 10, 11]).unwrap(), 4);

            // writer dropped, should flush now
        }

        assert_eq!(
            &buf[..],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, b'\r', b'\n', 10, 11][..]
        );
    }

    macro_rules! test_len {
        ( $name:ident, $len:ty ) => {
            #[test]
            fn $name() {
                use rand::{Rng, SeedableRng, XorShiftRng};
                use std::io::Cursor;

                let rng = &mut XorShiftRng::from_seed([
                    0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
                ]);
                let mut buf = Vec::new();

                let mut list = Vec::new();
                {
                    let mut c = Cursor::new(&mut buf);
                    let mut w = LineWriter::<_, $len>::new(&mut c, LineBreak::Crlf);
                    for i in 0..100 {
                        let data = (0..i).map(|_| rng.gen()).collect::<Vec<_>>();
                        w.write(&data).unwrap();
                        list.extend(&data);
                    }
                }

                let len = <$len as typenum::Unsigned>::to_usize();
                let expected: Vec<u8> = list.chunks(len).fold(Vec::new(), |mut acc, line| {
                    acc.extend(line);

                    if line.len() == len {
                        acc.push(b'\r');
                        acc.push(b'\n');
                    }
                    acc
                });

                assert_eq!(&buf[..], &expected[..]);
            }
        };
    }

    test_len!(test_break_line_len_1, typenum::U1);
    test_len!(test_break_line_len_2, typenum::U2);
    test_len!(test_break_line_len_10, typenum::U10);
    test_len!(test_break_line_len_74, typenum::U74);
    test_len!(test_break_line_len_100, typenum::U100);
    test_len!(test_break_line_len_256, typenum::U256);
}
