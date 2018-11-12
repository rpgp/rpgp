use std::io;
use std::io::prelude::*;

use circular::Buffer;
use nom::types::CompleteByteSlice;
use nom::Context::Code;
use nom::{self, Needed, Offset};

use util::prefixed;

/// Reads base64 values from a given byte input, skipping any newlines.
#[derive(Debug)]
pub struct Base64Reader<R> {
    inner: R,
    buffer: Buffer,
    capacity: usize,
}

impl<R: Read> Base64Reader<R> {
    pub fn new(input: R) -> Self {
        Base64Reader {
            inner: input,
            buffer: Buffer::with_capacity(32 * 1024),
            capacity: 32 * 1024,
        }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Base64Reader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let n = into.len();

        println!("-- read Base64Reader {} ", n);
        // TODO: const/configurable
        let max_capacity = 1024 * 1024 * 1024;
        // how much data have we read into from our underlying source
        let mut read = 0;

        // how much dtat have we written into the target `into`
        let mut written = 0;
        let into_len = into.len();

        while written < into_len {
            let b = &mut self.buffer;
            let sz = self.inner.read(b.space())?;
            b.fill(sz);

            if b.available_data() == 0 {
                // return Err(io::Error::new(
                //     io::ErrorKind::Interrupted,
                //     "not enough data available",
                // ));
                break;
            }

            let mut needed = None;
            let mut next_line = 0;

            while written < into_len {
                let rem_len = into_len - written + next_line;
                read = {
                    let data = if rem_len < b.data().len() {
                        &b.data()[0..rem_len]
                    } else {
                        b.data()
                    };

                    println!("reading: {} {:?}", data.len(), data);

                    match prefixed(CompleteByteSlice(data)) {
                        Ok((remaining, body_bytes)) => {
                            println!("got {:?} {} {:?}", body_bytes, body_bytes.len(), remaining);

                            if body_bytes.len() == 0 {
                                break;
                            }

                            into[written..written + body_bytes.len()].copy_from_slice(&body_bytes);
                            written += body_bytes.len();

                            if remaining.len() > 0 {
                                next_line = if remaining[0] == b'\n' {
                                    1
                                } else if remaining[0] == b'\r' {
                                    2
                                } else {
                                    0
                                };
                            }

                            b.data().offset(&remaining)
                        }
                        Err(nom::Err::Incomplete(n)) => {
                            needed = Some(n);
                            break;
                        }
                        Err(nom::Err::Error(Code(i, k))) => {
                            return Ok(written);
                        }
                        Err(nom::Err::Failure(Code(i, k))) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("failure {:?} {:?}", i, k),
                            ));
                        }
                    }
                };

                b.consume(read);

                // break if we filled the input
                if read == into_len {
                    break;
                }

                if let Some(Needed::Size(sz)) = needed {
                    if sz > b.capacity() && self.capacity * 2 < max_capacity {
                        self.capacity *= 2;
                        b.grow(self.capacity);
                    }
                }
            }
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

    fn read_exact(data: &[u8], size: usize) -> Vec<u8> {
        let mut c = Cursor::new(data);
        let mut r = Base64Reader::new(c);
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
            let mut c = Cursor::new(&data_with_garbage[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 33];
            r.read(&mut buf).unwrap();

            assert_eq!(&buf[0..33], &data_with_garbage[0..33]);
        }

        {
            let mut c = Cursor::new(&b"\n--"[..]);
            let mut r = Base64Reader::new(c);
            let mut buf = vec![0; 34];
            assert_eq!(r.read(&mut buf).unwrap(), 0);

            // match res {
            //     Ok(_) => panic!("should have errored"),
            //     Err(err) => {
            //         assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            //     }
            // }
        }
    }

    #[test]
    fn test_base64_reader_nr_lineending() {
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
