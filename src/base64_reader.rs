//! # base64 reader module

use std::io;
use std::io::prelude::*;

use crate::util::is_base64_token;

/// Reads base64 values from a given byte input, stops once it detects the first non base64 char.
#[derive(Debug)]
pub struct Base64Reader<R> {
    inner: R,
}

impl<R: Read> Base64Reader<R> {
    /// Creates a new `Base64Reader`.
    pub fn new(input: R) -> Self {
        Base64Reader { inner: input }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> BufRead for Base64Reader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let buf = self.inner.fill_buf()?;
        if buf.is_empty() {
            return Ok(&[][..]);
        }

        // Check for any non base64 tokens
        let max_good = buf.iter().position(|token| !is_base64_token(*token));

        if let Some(max_good) = max_good {
            return Ok(&buf[..max_good]);
        }

        Ok(buf)
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

impl<R: BufRead> Read for Base64Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rem = self.fill_buf()?;
        let n = rem.read(buf)?;
        self.consume(n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Cursor;

    use crate::line_reader::LineReader;

    fn read_exact(data: &[u8], size: usize) -> Vec<u8> {
        let c = Cursor::new(data);
        let lr = LineReader::new(c);
        let mut r = Base64Reader::new(lr);
        let mut buf = vec![0; size];
        r.read_exact(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_base64_reader_n_lineending() {
        let data = b"mQGiBEigu7MRBAD7gZJzevtYLB3c1pE7uMwu+zHzGGJDrEyEaz0lYTAaJ2YXmJ1+\n\
                     IvmvBI/iMrRqpFLR35uUcz2UHgJtIP+xenCF4WIhHv5wg3XvBvTgG/ooZaj1gtez\n\
                     miXV2bXTlEMxSqsZKvkieQRrMv3eV2VYhgaPvp8xJhl+xs8eVhlrmMv94wCgzWUw\n\
                     BrOICLPF5lANocvkqGNO3UUEAMH7GguhvXNlIUncqOpHC0N4FGPirPh/6nYxa9iZ\n\
                     kQEEg6mB6wPkaHZ5ddpagzFC6AncoOrhX5HPin9T6+cPhdIIQMogJOqDZ4xsAYCY\n\
                     KwjkoLQjfMdS5CYrMihFm4guNMKpWPfCe/T4TU7tFmTug8nnAIPFh2BNm8/EqHpg";

        // no new lines
        assert_eq!(read_exact(data, 10), &data[0..10]);

        // one new line
        assert_eq!(read_exact(data, 66), [&data[0..64], &data[65..67]].concat());

        // two new lines
        assert_eq!(
            read_exact(data, 130),
            [&data[0..64], &data[65..129], &data[130..132]].concat()
        );

        // all
        assert_eq!(
            read_exact(data, 6 * 64),
            [
                &data[0..64],
                &data[65..129],
                &data[130..194],
                &data[195..259],
                &data[260..324],
                &data[325..],
            ]
            .concat()
        );

        let data_with_garbage = b"KwjkoLQjfMdS5CYrMihFm4guNMKpWPfCe\n--";
        assert_eq!(
            read_exact(&data_with_garbage[..], 10),
            &data_with_garbage[0..10]
        );

        assert_eq!(
            read_exact(&data_with_garbage[..], 33),
            &data_with_garbage[0..33],
        );

        {
            let c = Cursor::new(&data_with_garbage[..]);
            let lr = LineReader::new(c);
            let mut r = Base64Reader::new(lr);
            let mut buf = vec![0; 35];
            assert_eq!(r.read(&mut buf).unwrap(), 33);

            assert_eq!(&buf[0..33], &data_with_garbage[0..33]);
        }

        {
            let c = Cursor::new(&b"Kw--"[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 5];
            assert_eq!(r.read(&mut buf).unwrap(), 2);
            assert_eq!(buf, vec![b'K', b'w', 0, 0, 0]);
            assert_eq!(r.into_inner().position(), 2);
        }

        {
            // Checksum at the end of ascii armor
            let c = Cursor::new(&b"Kwjk\n=Kwjk"[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 10];
            assert_eq!(r.read(&mut buf).unwrap(), 10);
            assert_eq!(&buf[..], b"Kwjk\n=Kwjk");
            assert_eq!(r.into_inner().position(), 10);
        }

        {
            // Leave things alone that are not us
            let c = Cursor::new(&b"Kwjk\n-----BEGIN"[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 5);
            assert_eq!(r.into_inner().position(), 5);
            assert_eq!(&buf[..5], b"Kwjk\n");
            assert_eq!(&buf[5..], &vec![0u8; 95][..]);
        }

        {
            // Leave things alone that are not us
            let c = Cursor::new(&b"Kwjk\n-----BEGIN-----\nKwjk\n"[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 5);
            assert_eq!(&buf[..5], b"Kwjk\n");
            assert_eq!(&buf[5..], &vec![0u8; 95][..]);
        }
    }
}
