use std::io;
use std::io::prelude::*;

use util::is_base64_token;

/// Reads base64 values from a given byte input, stops once it detects the first non base64 char.
#[derive(Debug)]
pub struct Base64Reader<R> {
    inner: R,
}

impl<R: Read> Base64Reader<R> {
    pub fn new(input: R) -> Self {
        Base64Reader { inner: input }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Base64Reader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(into)?;

        for i in 0..n {
            if !is_base64_token(into[i]) {
                // the party is over

                for j in i..n {
                    into[j] = 0;
                }

                return Ok(i);
            }
        }

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

    use line_reader::LineReader;

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
        assert_eq!(
            read_exact(data, 66),
            vec![&data[0..64], &data[65..67]].concat()
        );

        // two new lines
        assert_eq!(
            read_exact(data, 130),
            vec![&data[0..64], &data[65..129], &data[130..132]].concat()
        );

        // all
        assert_eq!(
            read_exact(data, 6 * 64),
            vec![
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
        }
    }
}
