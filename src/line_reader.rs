use std::io;
use std::io::prelude::*;

/// Reads arbitrary values from a given byte input, skipping any newlines.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
}

impl<R: Read> LineReader<R> {
    pub fn new(input: R) -> Self {
        LineReader { inner: input }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for LineReader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut n = self.inner.read(into)?;

        while n > 0 {
            let mut offset = 0;
            for i in 0..n {
                let b = into[i];
                if b != b'\r' && b != b'\n' {
                    // if we have an offset, we need to shift all values
                    if i != offset {
                        into[offset] = b;
                    }
                    offset += 1;
                }
            }
            if offset > 0 {
                return Ok(offset);
            }

            // we only read whitespace, lets read some more
            n = self.inner.read(into)?;
        }

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

    fn read_exact(data: &[u8], size: usize) -> Vec<u8> {
        let c = Cursor::new(data);
        let mut r = LineReader::new(c);
        let mut buf = vec![0; size];
        r.read_exact(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_line_reader_n_lineending() {
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
            let mut r = LineReader::new(c);
            let mut buf = vec![0; 33];
            r.read(&mut buf).unwrap();

            assert_eq!(&buf[0..33], &data_with_garbage[0..33]);
        }

        {
            let c = Cursor::new(&b"\n--"[..]);
            let mut r = LineReader::new(c);
            let mut buf = vec![0; 34];
            assert_eq!(r.read(&mut buf).unwrap(), 2);
            assert_eq!(&buf[0..2], &b"--"[..]);
        }
    }

    #[test]
    fn test_line_reader_nr_lineending() {
        let data = b"mQGiBEigu7MRBAD7gZJzevtYLB3c1pE7uMwu+zHzGGJDrEyEaz0lYTAaJ2YXmJ1+\r\n\
                    IvmvBI/iMrRqpFLR35uUcz2UHgJtIP+xenCF4WIhHv5wg3XvBvTgG/ooZaj1gtez\r\n\
                    miXV2bXTlEMxSqsZKvkieQRrMv3eV2VYhgaPvp8xJhl+xs8eVhlrmMv94wCgzWUw\r\n\
                    BrOICLPF5lANocvkqGNO3UUEAMH7GguhvXNlIUncqOpHC0N4FGPirPh/6nYxa9iZ\r\n\
                    kQEEg6mB6wPkaHZ5ddpagzFC6AncoOrhX5HPin9T6+cPhdIIQMogJOqDZ4xsAYCY\r\n\
                    KwjkoLQjfMdS5CYrMihFm4guNMKpWPfCe/T4TU7tFmTug8nnAIPFh2BNm8/EqHpg";

        // no new lines
        assert_eq!(read_exact(data, 10), &data[0..10]);

        // one new line
        assert_eq!(
            read_exact(data, 66),
            vec![&data[0..64], &data[66..68]].concat()
        );

        // two new lines
        assert_eq!(
            read_exact(data, 130),
            vec![&data[0..64], &data[66..130], &data[132..134]].concat()
        );

        // all
        assert_eq!(
            read_exact(data, 6 * 64),
            vec![
                &data[0..64],
                &data[66..130],
                &data[132..196],
                &data[198..262],
                &data[264..328],
                &data[330..],
            ]
            .concat()
        );
    }
}
