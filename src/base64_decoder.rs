use std::error::Error;
use std::io::{self, BufRead, Read, Seek, Write};

use buf_redux::{BufReader, Buffer as ReBuffer};
use circular::Buffer;

use base64::{decode_config_slice, CharacterSet, Config};

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;

/// Decodes Base64 from the supplied reader.
pub struct Base64Decoder<R> {
    /// What configuration to use for decoding.
    config: Config,
    /// The inner Read instance we are reading bytes from.
    inner: BufReader<R>,
    /// leftover decoded output
    out: Buffer,
    ///
    out_buffer: [u8; BUF_CAPACITY],
    /// Memorize if we had an error, so we can return it on calls to read again.
    err: Option<io::Error>,
}

impl<R: Read + Seek> Base64Decoder<R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Self::new_with_character_set(input, CharacterSet::Standard)
    }

    pub fn new_with_character_set(input: R, cs: CharacterSet) -> Self {
        Base64Decoder {
            config: Config::new(cs, true),
            inner: BufReader::with_capacity(BUF_SIZE, input),
            out: Buffer::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }

    pub fn into_inner_with_buffer(self) -> (R, ReBuffer) {
        self.inner.into_inner_with_buffer()
    }
}

impl<R: Read + Seek> Read for Base64Decoder<R> {
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
        if self.inner.buf_len() < 4 {
            let b = &mut self.inner;

            match b.read_into_buf() {
                Err(err) => {
                    self.err = Some(copy_err(&err));
                    return Err(err);
                }
                _ => {}
            }
        }

        let nr = self.inner.buf_len() / 4 * 4;
        let nw = self.inner.buf_len() / 4 * 3;

        let (consumed, written) = if nw > into.len() {
            let (consumed, nw) = try_decode_config_slice(
                &self.inner.buffer()[..nr],
                self.config,
                &mut self.out_buffer[..],
            );

            let n = ::std::cmp::min(nw, into.len());
            let t = &self.out_buffer[0..nw];
            let (t1, t2) = t.split_at(n);

            // copy what we have into `into`
            into[0..n].copy_from_slice(t1);
            // store the rest
            self.out.write(t2)?;

            (consumed, n)
        } else {
            try_decode_config_slice(&self.inner.buffer()[..nr], self.config, into)
        };

        self.inner.consume(consumed);

        Ok(written)
    }
}

/// Tries to decode as much of the given slice as possible.
/// Returns the amount written and consumed.
fn try_decode_config_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    config: Config,
    output: &mut [u8],
) -> (usize, usize) {
    let input_bytes = input.as_ref();
    let mut n = input_bytes.len();
    while n > 0 {
        match decode_config_slice(&input_bytes[0..n], config, output) {
            Ok(size) => {
                return (n, size);
            }
            Err(_) => {
                if n % 4 != 0 {
                    n -= n % 4
                } else {
                    n -= 4
                }
            }
        }
    }

    (0, 0)
}

// why, why why????
fn copy_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), err.description())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use base64::{encode_config, CharacterSet, Config};
    use rand::{Rng, SeedableRng, XorShiftRng};

    use base64_reader::Base64Reader;
    use line_reader::LineReader;

    fn test_roundtrip(cs: CharacterSet, n: usize) {
        let rng = &mut XorShiftRng::from_seed([
            0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
        ]);

        for i in 0..n {
            let data: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let encoded_data = encode_config(&data, Config::new(cs, true));

            let mut r = Base64Decoder::new_with_character_set(Cursor::new(encoded_data), cs);
            let mut out = Vec::new();

            r.read_to_end(&mut out).unwrap(); //("failed to decode");
            assert_eq!(data, out);
        }
    }

    #[test]
    fn test_base64_decoder_roundtrip_standard_1000() {
        test_roundtrip(CharacterSet::Standard, 1000);
    }

    #[test]
    fn test_base64_decoder_roundtrip_crypt_1000() {
        test_roundtrip(CharacterSet::Crypt, 1000);
    }

    #[test]
    fn test_base64_decoder_roundtrip_url_safe_1000() {
        test_roundtrip(CharacterSet::UrlSafe, 1000);
    }

    #[test]
    fn test_base64_decoder_with_line_reader() {
        let source = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        let data = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2Qgd\n\
                     GVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0\n\
                     gdmVuaWFtLCBxdWlz\n\
                     IG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZW\n\
                     EgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2\n\
                     xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF\n\
                     0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZm\n\
                     ZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";

        let c = Cursor::new(&data[..]);
        let lr = LineReader::new(c);
        let mut reader = Base64Decoder::new(lr);
        let mut res = String::new();

        reader.read_to_string(&mut res).unwrap();
        assert_eq!(source, res);
    }

    #[test]
    fn test_base64_decoder_with_end() {
        let data = b"TG9yZW0g\n=TG9y\n-----hello";

        let c = Cursor::new(&data[..]);
        let lr = LineReader::new(c);
        let br = Base64Reader::new(lr);
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner().into_inner();

        assert_eq!(buffer.buf(), b"=TG9y");
        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 10);
        assert_eq!(&rest, b"-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_one_linebreak() {
        let data = b"TG9yZW0g\n=TG9y-----hello";

        let c = Cursor::new(&data[..]);
        let lr = LineReader::new(c);
        let br = Base64Reader::new(lr);
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner().into_inner();

        assert_eq!(buffer.buf(), b"=TG9y");
        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 10);
        assert_eq!(&rest, b"-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_no_linebreak() {
        let data = b"TG9yZW0g=TG9y-----hello";

        let c = Cursor::new(&data[..]);
        let lr = LineReader::new(c);
        let br = Base64Reader::new(lr);
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner().into_inner();

        assert_eq!(buffer.buf(), b"=TG9y");
        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 10);
        assert_eq!(&rest, b"-----hello");
    }
}
