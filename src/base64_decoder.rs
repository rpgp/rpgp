//! # base64 decoder module

use std::fmt;
use std::io::{self, BufRead, Read};

use base64::engine::{
    general_purpose::{GeneralPurpose, PAD},
    Engine,
};
use buffer_redux::Buffer;

use crate::util::is_base64_token;

const BUF_SIZE: usize = 1024;
const ENGINE: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::STANDARD, PAD);
const MAX_INPUT: Option<usize> = base64::encoded_len(BUF_SIZE, true);

/// Decodes Base64 from the supplied reader.
///
/// - skipping any new lines
/// - stops at the first non base64 encoded character.
pub struct Base64Decoder<R: BufRead> {
    /// The inner Read instance we are reading bytes from.
    inner: R,
    /// Out buffer, contains decoded base64.
    buffer: Buffer,
    /// Fixed buffer for base64 decoding
    fixed_buffer: [u8; BUF_SIZE],
}

impl<R: BufRead> fmt::Debug for Base64Decoder<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Base64Decoder")
            .field("inner", &"BufRead")
            .field("buffer", &hex::encode(self.buffer.buf()))
            .field("fixed_buffer", &hex::encode(&self.fixed_buffer))
            .finish()
    }
}

impl<R: BufRead> Base64Decoder<R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(inner: R) -> Self {
        Base64Decoder {
            inner,
            buffer: Buffer::with_capacity(BUF_SIZE),
            fixed_buffer: [0u8; BUF_SIZE],
        }
    }
}

impl<R: BufRead> Base64Decoder<R> {
    #[cfg(test)]
    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        (self.inner, self.buffer)
    }
}

#[inline]
fn is_line_break(t: u8) -> bool {
    t == b'\r' || t == b'\n'
}

impl<R: BufRead> BufRead for Base64Decoder<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let mut mini_buffer = [0u8; 4];

        let Self {
            inner,
            buffer,
            fixed_buffer,
        } = self;

        while buffer.is_empty() {
            let buf = inner.fill_buf()?;
            if buf.is_empty() {
                return Ok(&[][..]);
            }

            // Check for any non base64 tokens
            let max_good = buf.iter().position(|token| !is_base64_token(*token));
            let buf = match max_good {
                Some(max_good) => &buf[..max_good],
                None => buf,
            };

            // Search for line breaks
            let (buf, skip) = match memchr::memchr2(b'\r', b'\n', buf) {
                Some(pos) => {
                    let skip = if buf.len() > pos + 1 {
                        match buf[pos + 1..].iter().position(|t| !is_line_break(*t)) {
                            Some(end_pos) => {
                                // skip this many line breaks
                                end_pos + 1
                            }
                            None => {
                                // only line breaks in the current buffer
                                let l = buf.len();
                                inner.consume(l);
                                continue;
                            }
                        }
                    } else {
                        1
                    };

                    // Need at least a buffer of size 4 to continue
                    if pos < 4 && buf.len() >= 4 - pos {
                        mini_buffer[..pos].copy_from_slice(&buf[..pos]);
                        let mut new_skip = skip;
                        let mut written = pos;

                        while written < 4 {
                            if !is_line_break(buf[written + new_skip]) {
                                mini_buffer[written] = buf[written + new_skip];
                                written += 1;
                            } else {
                                new_skip += 1;
                            }
                        }

                        (&mini_buffer[..], new_skip)
                    } else {
                        // use up to the found break
                        (&buf[..pos], skip)
                    }
                }
                None => {
                    // use the whole buffer
                    (buf, 0)
                }
            };

            if buf.len() < 4 {
                // trailing padding
                if buf.iter().all(|b| *b == b'=') {
                    let rest = buf.len();
                    inner.consume(rest);
                    break;
                }

                // error
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid trailing data: '{:?}'", buf),
                ));
            }

            let mut consumed = try_decode_engine_slice(buf, fixed_buffer, buffer);

            if consumed == 0 {
                // No valid data available anymore
                break;
            }

            if consumed == buf.len() {
                // If we consumed the whole buffer, consume the line breaks from the inner as well.
                consumed += skip;
            }

            // mark the part we decoded as consumed
            inner.consume(consumed);
        }

        Ok(buffer.buf())
    }

    fn consume(&mut self, amt: usize) {
        self.buffer.consume(amt);
    }
}

impl<R: BufRead> Read for Base64Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rem = self.fill_buf()?;
        let n = rem.read(buf)?;
        self.consume(n);
        Ok(n)
    }
}

/// Tries to decode as much of the given slice as possible.
/// Returns the amount consumed.
fn try_decode_engine_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    buffer: &mut [u8; BUF_SIZE],
    output: &mut Buffer,
) -> usize {
    let input_bytes = input.as_ref();
    let mut n = std::cmp::min(input_bytes.len(), MAX_INPUT.expect("checked"));

    while n > 0 {
        match ENGINE.decode_slice(&input_bytes[..n], &mut buffer[..]) {
            Ok(size) => {
                output.copy_from_slice(&buffer[..size]);
                return n;
            }
            Err(_err) => {
                if n % 4 != 0 {
                    n -= n % 4
                } else {
                    n -= 4
                }
            }
        }
    }

    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use std::io::{BufReader, Cursor};

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    fn test_roundtrip(cap: usize, n: usize) {
        let rng = &mut XorShiftRng::from_seed([
            0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
        ]);

        for i in 0..n {
            let data: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let encoded_data = ENGINE.encode(&data);

            let inner = BufReader::with_capacity(cap, Cursor::new(encoded_data));
            let mut r = Base64Decoder::new(inner);
            let mut out = Vec::new();

            r.read_to_end(&mut out).unwrap();
            assert_eq!(data, out);
        }
    }

    #[test]
    fn test_base64_decoder_roundtrip_1000() {
        test_roundtrip(8, 1000);
        test_roundtrip(64, 1000);
        test_roundtrip(128, 1000);
        test_roundtrip(1000, 1000);
        test_roundtrip(8 * 1024, 1000);
    }

    #[test]
    fn test_base64_decoder_with_lines() {
        let cases = [
            (
               "Lorem Lorem Lorem ",
               "TG9\nyZW\n0g\nTG9y\nZW0g\nTG9y\nZW0g\n",
            ),
            (
               "Lorem Lorem Lorem ",
               "TG9\r\nyZW\n0g\r\nTG9y\nZW0g\nTG9y\nZW0g\n",
            ),
            (
               "Lorem Lorem Lorem ",
               "\n\n\n\r\nTG9\r\nyZW\n\n\n\n0g\r\nTG9y\n\n\n\n\nZW0g\nTG9y\nZW0g\n\n\n",
            ),
            (
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
                "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2Qgd\n\
                 GVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0\n\
                 gdmVuaWFtLCBxdWlz\n\
                 IG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZW\n\
                 EgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2\n\
                 xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF\n\
                 0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZm\n\
                 ZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg=="
            )
        ];

        for (source, data) in cases {
            let c = Cursor::new(data.as_bytes());
            let mut reader = Base64Decoder::new(c);
            let mut res = Vec::new();
            reader.read_to_end(&mut res).unwrap();

            let res_str = String::from_utf8_lossy(&res);
            assert_eq!(source, res_str);
        }
    }

    #[test]
    fn test_base64_decoder_with_end_base() {
        let data = b"TG9yZW0g\n=TG9y\n-----hello";

        let c = Cursor::new(&data[..]);
        let mut reader = Base64Decoder::new(c);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (mut r, buffer) = reader.into_inner_with_buffer();
        assert!(buffer.is_empty());

        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 16);
        assert_eq!(&rest, b"=TG9y\n-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_one_linebreak() {
        let data = b"TG9yZW0g\n=TG9y-----hello";

        let c = Cursor::new(&data[..]);
        let mut reader = Base64Decoder::new(c);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (mut r, buffer) = reader.into_inner_with_buffer();
        assert!(buffer.is_empty());

        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 15);
        assert_eq!(&rest, b"=TG9y-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_no_linebreak() {
        let data = b"TG9yZW0g=TG9y-----hello";

        let c = Cursor::new(&data[..]);
        let mut reader = Base64Decoder::new(c);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (mut r, buffer) = reader.into_inner_with_buffer();

        dbg!(std::str::from_utf8(buffer.buf()).unwrap());
        assert!(buffer.is_empty());

        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 15);
        assert_eq!(&rest, b"=TG9y-----hello");
    }

    fn read_exact(data: &[u8], size: usize) -> String {
        let c = Cursor::new(data);
        let mut r = Base64Decoder::new(c);
        let mut buf = vec![0; size];
        r.read_exact(&mut buf).unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    fn s(data: &[u8]) -> String {
        String::from_utf8(data.to_vec()).unwrap()
    }

    #[test]
    fn test_base64_decoder_n_lineending() {
        let data = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np\n\
                          bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFi\n\
                          b3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVu\n\
                          aWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBu\n\
                          aXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0\n\
                          ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxp\n\
                          dCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBF\n\
                          eGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBz\n\
                          dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlk\n\
                          IGVzdCBsYWJvcnVtLg==";

        // no new lines
        assert_eq!(read_exact(data, 10), "Lorem ipsu");

        // one new line
        assert_eq!(
            read_exact(data, 66),
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ei"
        );

        // two new lines
        assert_eq!(
            read_exact(data, 130),
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut eni",
        );

        let data_with_garbage =
            b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np\n--";
        assert_eq!(read_exact(&data_with_garbage[..], 10), "Lorem ipsu",);

        {
            let c = Cursor::new(&data_with_garbage[..]);
            let mut r = Base64Decoder::new(c);
            let mut buf = vec![0; 70];
            assert_eq!(r.read(&mut buf).unwrap(), 48);

            assert_eq!(
                s(&buf[..48]),
                "Lorem ipsum dolor sit amet, consectetur adipisci"
            );
        }

        {
            // Checksum at the end of ascii armor
            let c = Cursor::new(&b"TG9y\n=Kwjk"[..]);
            let mut r = Base64Decoder::new(c);
            let mut buf = vec![0; 10];
            assert_eq!(r.read(&mut buf).unwrap(), 3);
            assert_eq!(s(&buf[..3]), "Lor");
            assert_eq!(r.into_inner().position(), 5);
        }

        {
            // Leave things alone that are not us
            let c = Cursor::new(&b"TG9y\n-----BEGIN"[..]);
            let mut r = Base64Decoder::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 3);
            assert_eq!(r.into_inner().position(), 5);
            assert_eq!(s(&buf[..3]), "Lor");
            assert_eq!(&buf[3..], &vec![0u8; 97][..]);
        }

        {
            // Leave things alone that are not us
            let c = Cursor::new(&b"TG9y\n-----BEGIN-----\nKwjk\n"[..]);
            let mut r = Base64Decoder::new(c);
            let mut buf = vec![0; 100];
            assert_eq!(r.read(&mut buf).unwrap(), 3);
            assert_eq!(s(&buf[..3]), "Lor");
            assert_eq!(&buf[3..], &vec![0u8; 97][..]);
        }
    }
}
