use std::error::Error;
use std::io::{self, Read, Write};

use circular::Buffer;

use base64::Base64Reader;
use base64_crate::{decode_config_slice, DecodeError, STANDARD};

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;

pub struct Base64Decoder<R> {
    inner: Base64Reader<R>,
    // leftover input
    buffer: Buffer,
    // leftover decoded output
    out: Buffer,
    out_buffer: [u8; BUF_CAPACITY],
    err: Option<io::Error>,
}

impl<R: Read> Base64Decoder<R> {
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: Base64Reader::new(input),
            buffer: Buffer::with_capacity(BUF_SIZE),
            out: Buffer::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }
}

fn to_io(err: &DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("decoder: {:?}", err))
}

// why, why why????
fn copy_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), err.description())
}

impl<R: Read> Read for Base64Decoder<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        // take care of leftovers
        if !self.out.empty() {
            let len = ::std::cmp::min(into.len(), self.out.available_data());
            into[0..len].copy_from_slice(&self.out.data()[0..len]);
            self.out.consume(len);

            return Ok(len);
        }

        // if we had an error before, return it
        if let Some(ref err) = self.err {
            return Err(copy_err(err));
        }

        // fill our buffer
        if self.buffer.available_data() < 4 {
            let b = &mut self.buffer;

            match self.inner.read(b.space()) {
                Ok(sz) => {
                    b.fill(sz);
                }
                Err(err) => {
                    self.err = Some(copy_err(&err));
                    return Err(err);
                }
            }
        }

        let nr = self.buffer.available_data() / 4 * 4;
        let nw = self.buffer.available_data() / 4 * 3;
        println!("decoding: {:?}", &self.buffer.data()[..nr]);

        let n = if nw > into.len() {
            match decode_config_slice(
                &self.buffer.data()[..nr],
                STANDARD,
                &mut self.out_buffer[..],
            ) {
                Ok(nw) => {
                    let n = into.len();
                    self.out.write(&self.out_buffer[n..nw])?;
                    into.copy_from_slice(&self.out_buffer[0..n]);
                    n
                }
                Err(ref err) => {
                    self.err = Some(to_io(err));
                    return Err(to_io(err));
                }
            }
        } else {
            match decode_config_slice(&self.buffer.data()[..nr], STANDARD, into) {
                Ok(n) => n,
                Err(ref err) => {
                    self.err = Some(to_io(err));
                    return Err(to_io(err));
                }
            }
        };

        self.buffer.consume(nr);

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

    #[test]
    fn test_base64_decode() {
        let source = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        let data = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2Qgd\n\
                     GVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0\n\
                     gdmVuaWFtLCBxdWlz\n\
                     IG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZW\n\
                     EgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2\n\
                     xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF\n\
                     0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZm\n\
                     ZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";

        let mut c = Cursor::new(&data[..]);
        let mut reader = Base64Decoder::new(c);
        let mut res = String::new();

        reader.read_to_string(&mut res).unwrap();
        assert_eq!(source, res);
    }
}
