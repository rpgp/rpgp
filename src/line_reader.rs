use std::io;
use std::io::prelude::*;

/// Reads arbitrary values from a given byte input, skipping any newlines.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    /// Positions into the `inner` reader at which line breaks where detected.
    // FIXME: limit the size of this.
    lines: Vec<u64>,
    last_stored_pos: u64,
}

impl<R: Read + Seek> LineReader<R> {
    pub fn new(input: R) -> Self {
        LineReader {
            inner: input,
            lines: Vec::with_capacity(32),
            last_stored_pos: 0,
        }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Seek for LineReader<R> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match pos {
            io::SeekFrom::Current(n) => {
                let mut seek_pos = if n < 0 { (-n) } else { n } as u64;

                let current_pos = self.inner.seek(io::SeekFrom::Current(0))?;

                // count lines we need to add to our seek
                for line_break_pos in self.lines.iter().rev() {
                    if seek_pos < current_pos - *line_break_pos {
                        break;
                    }
                    seek_pos += 1;
                }

                self.inner.seek(io::SeekFrom::Current(-(seek_pos as i64)))
            }
            _ => unimplemented!(),
        }
    }
}

impl<R: Read + Seek> Read for LineReader<R> {
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
                } else {
                    // store the line break position
                    let r_pos = self.inner.seek(io::SeekFrom::Current(0))?;
                    let offset = (r_pos - n as u64) + i as u64;

                    // As we might be going back and forth in the source, we need to make sure
                    // to only store newly discovered line breaks.
                    if offset > self.last_stored_pos {
                        self.lines.push(offset);
                        self.last_stored_pos = offset;
                    }
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
            r.read_exact(&mut buf).unwrap();

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

    #[test]
    fn test_line_reader_seek() {
        let input = b"hellonworld-";
        let c = Cursor::new(&input[..]);
        let mut r = LineReader::new(c);

        let mut buf = vec![0; input.len() + 2];
        assert_eq!(r.read(&mut buf).unwrap(), input.len());
        assert_eq!(&buf[..input.len()], &input[..]);

        // seek
        assert_eq!(r.seek(io::SeekFrom::Current(-8)).unwrap(), 4);

        let mut buf = vec![0; input.len()];
        assert_eq!(r.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf[..input.len() - 4], &input[4..]);
    }

    #[test]
    fn test_line_reader_seek_forward() {
        let input = b"hellonworld-";
        let c = Cursor::new(&input[..]);
        let mut r = LineReader::new(c);

        let mut buf = vec![0; input.len() + 2];
        assert_eq!(r.read(&mut buf).unwrap(), input.len());
        assert_eq!(&buf[..input.len()], &input[..]);

        // seek
        assert_eq!(r.seek(io::SeekFrom::Current(-10)).unwrap(), 2);
        assert_eq!(r.seek(io::SeekFrom::Current(4)).unwrap(), 6);
        assert_eq!(r.seek(io::SeekFrom::Current(-2)).unwrap(), 4);

        let mut buf = vec![0; input.len()];
        assert_eq!(r.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf[..input.len() - 4], &input[4..]);
    }

    #[test]
    fn test_line_reader_seek_mix_1() {
        let input = b"ab\ncd\nef\ngh";
        //           "ab cd ef gh"
        let c = Cursor::new(&input[..]);
        let mut r = LineReader::new(c);

        let mut buf = vec![0; input.len()];
        assert_eq!(r.read(&mut buf).unwrap(), input.len() - 3);
        assert_eq!(
            std::str::from_utf8(&buf[..input.len() - 3]).unwrap(),
            "abcdefgh"
        );
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(&r.lines, &vec![2, 5, 8]);

        // seek
        assert_eq!(r.seek(io::SeekFrom::Current(-5)).unwrap(), 4);

        let mut buf = vec![0; input.len()];
        let mut r_inner = r.into_inner();
        let read = r_inner.read(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(&buf[..read]).unwrap(), "d\nef\ngh");
    }

    #[test]
    fn test_line_reader_seek_mix_2() {
        let input = b"ab\ncd\nef\ngh";
        //           "ab cd ef gh"
        let c = Cursor::new(&input[..]);
        let mut r = LineReader::new(c);

        let mut buf = vec![0; input.len()];
        assert_eq!(r.read(&mut buf).unwrap(), input.len() - 3);
        assert_eq!(
            std::str::from_utf8(&buf[..input.len() - 3]).unwrap(),
            "abcdefgh"
        );
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(&r.lines, &vec![2, 5, 8]);

        // seek
        assert_eq!(
            r.seek(io::SeekFrom::Current(-(input.len() as i64 - 3)))
                .unwrap(),
            0
        );

        let mut buf = vec![0; input.len()];
        let mut r_inner = r.into_inner();
        let read = r_inner.read(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(&buf[..read]).unwrap(), "ab\ncd\nef\ngh");
    }
}
