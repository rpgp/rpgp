//! # base64 reader module

use std::io;
use std::io::prelude::*;

/// Reads base64 values from a given byte input, stops once it detects the first non base64 char.
#[derive(Debug)]
pub struct Base64Reader<R: BufRead> {
    inner: R,
}

impl<R: BufRead> Base64Reader<R> {
    /// Creates a new `Base64Reader`.
    pub fn new(input: R) -> Self {
        Base64Reader { inner: input }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Read for Base64Reader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut buf = self.inner.fill_buf()?;
        if buf.is_empty() {
            return Ok(0);
        }

        let mut buf_i = 0;
        let mut n = 0;
        loop {
            // skip new lines
            while buf[buf_i] == b'\r' || buf[buf_i] == b'\n' {
                buf_i += 1;
                if buf_i == buf.len() {
                    break;
                }
            }

            if buf_i < buf.len() {
                if !is_base64_token(buf[buf_i]) {
                    break;
                }

                into[n] = buf[buf_i];
                n += 1;
                buf_i += 1;
                if n == into.len() {
                    break;
                }
            }

            if buf_i == buf.len() {
                self.inner.consume(buf_i);
                buf = self.inner.fill_buf()?;
                buf_i = 0;
                if buf.is_empty() {
                    break;
                }
            }
        }

        self.inner.consume(buf_i);

        Ok(n)
    }
}

#[inline]
fn is_base64_token(c: u8) -> bool {
    ((0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c))
        // alphabetic
        || (0x30..=0x39).contains(&c) //  digit
        || c == b'/'
        || c == b'+'
        || c == b'='
        || c == b'\n'
        || c == b'\r'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_exact(data: &[u8], size: usize) -> Vec<u8> {
        let mut r = Base64Reader::new(data);
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
            let mut r = Base64Reader::new(&data_with_garbage[..]);
            let mut buf = vec![0; 35];
            assert_eq!(r.read(&mut buf).unwrap(), 33);

            assert_eq!(&buf[0..33], &data_with_garbage[0..33]);
        }

        {
            let c = &b"Kw--"[..];
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 5];
            assert_eq!(r.read(&mut buf).unwrap(), 2);
            assert_eq!(buf, vec![b'K', b'w', 0, 0, 0]);
        }

        {
            // Checksum at the end of ascii armor
            let c = &b"Kwjk\n=Kwjk"[..];
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 10];
            assert_eq!(r.read(&mut buf).unwrap(), 9);
            assert_eq!(&buf[..9], b"Kwjk=Kwjk");
        }

        {
            // Leave things alone that are not us
            let c = &b"Kwjk\n-----BEGIN"[..];
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 4);

            assert_eq!(&buf[..4], b"Kwjk");
            assert_eq!(&buf[4..], &vec![0u8; 96][..]);
        }

        {
            // Leave things alone that are not us
            let c = &b"Kwjk\n-----BEGIN-----\nKwjk\n"[..];
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 4);
            assert_eq!(&buf[..4], b"Kwjk");
            assert_eq!(&buf[4..], &vec![0u8; 96][..]);
        }
    }

    #[test]
    fn test_regression_long_key() {
        // skip first line ---BEGIN
        let input: String = std::fs::read_to_string("./tests/unit-tests/long-key.asc")
            .unwrap()
            .lines()
            .skip(1)
            .collect();

        let mut r = Base64Reader::new(input.as_bytes());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();

        let input_expected =
            std::fs::read_to_string("./tests/unit-tests/long-key.asc.expected").unwrap();
        let expected: String = input_expected.lines().collect();
        assert_eq!(std::str::from_utf8(&out).unwrap(), expected);
    }
}
