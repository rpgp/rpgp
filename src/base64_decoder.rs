//! # base64 decoder module

use std::fmt;
use std::io::{self, BufRead, Read};

use base64::{
    alphabet::Alphabet,
    engine::{
        general_purpose::{GeneralPurpose, PAD},
        Engine,
    },
};
use buffer_redux::{BufReader, Buffer};

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;

/// Decodes Base64 from the supplied reader.
pub struct Base64Decoder<E: Engine, R> {
    /// What base64 engine to use.
    engine: E,
    /// The inner Read instance we are reading bytes from.
    inner: BufReader<R>,
    /// leftover decoded output
    out: Buffer,
    ///
    out_buffer: [u8; BUF_CAPACITY],
    /// Memorize if we had an error, so we can return it on calls to read again.
    err: Option<io::Error>,
}

impl<E: Engine, R> fmt::Debug for Base64Decoder<E, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let out_buf = format!("{:?}", &self.out_buffer[..]);
        f.debug_struct("Base64Decoder")
            .field("engine", &"..")
            .field("inner", &"BufReader")
            .field("out", &self.out)
            .field("out_buffer", &out_buf)
            .field("err", &self.err)
            .finish()
    }
}

impl<R: Read> Base64Decoder<GeneralPurpose, R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Self::new_with_character_set(input, &base64::alphabet::STANDARD)
    }

    pub fn new_with_character_set(input: R, cs: &Alphabet) -> Self {
        Base64Decoder {
            engine: GeneralPurpose::new(cs, PAD),
            inner: BufReader::with_capacity(BUF_SIZE, input),
            out: Buffer::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }
}

impl<E: Engine, R: Read> Base64Decoder<E, R> {
    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        self.inner.into_inner_with_buffer()
    }
}

impl<E: Engine, R: Read> Read for Base64Decoder<E, R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        // take care of leftovers
        if !self.out.is_empty() {
            let len = self.out.copy_to_slice(into);

            return Ok(len);
        }

        // if we had an error before, return it
        if let Some(ref err) = self.err {
            return Err(copy_err(err));
        }

        // fill our buffer
        if self.inner.buf_len() < 4 {
            let b = &mut self.inner;

            if let Err(err) = b.read_into_buf() {
                self.err = Some(copy_err(&err));
                return Err(err);
            }
        }

        // short circuit empty read
        if self.inner.buf_len() == 0 {
            return Ok(0);
        }

        let nr = self.inner.buf_len() / 4 * 4;
        let nw = self.inner.buf_len() / 4 * 3;

        let (consumed, written) = if nw > into.len() {
            let (consumed, nw) = try_decode_engine_slice(
                &self.inner.buffer()[..nr],
                &self.engine,
                &mut self.out_buffer[..],
            );

            let n = std::cmp::min(nw, into.len());
            let t = &self.out_buffer[0..nw];
            let (t1, t2) = t.split_at(n);

            // copy what we have into `into`
            into[0..n].copy_from_slice(t1);
            // store the rest
            self.out.copy_from_slice(t2);

            (consumed, n)
        } else {
            try_decode_engine_slice(&self.inner.buffer()[..nr], &self.engine, into)
        };

        self.inner.consume(consumed);

        Ok(written)
    }
}

/// Tries to decode as much of the given slice as possible.
/// Returns the amount written and consumed.
fn try_decode_engine_slice<E: Engine, T: ?Sized + AsRef<[u8]>>(
    input: &T,
    engine: &E,
    output: &mut [u8],
) -> (usize, usize) {
    let input_bytes = input.as_ref();
    let mut n = input_bytes.len();
    while n > 0 {
        match engine.decode_slice(&input_bytes[..n], output) {
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
    io::Error::new(err.kind(), err.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use std::io::Cursor;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::base64_reader::Base64Reader;
    use crate::line_reader::LineReader;

    fn test_roundtrip(cs: Alphabet, n: usize) {
        let rng = &mut XorShiftRng::from_seed([
            0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
        ]);

        for i in 0..n {
            let data: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let engine = GeneralPurpose::new(&cs, PAD);
            let encoded_data = engine.encode(&data);

            let mut r = Base64Decoder::new_with_character_set(Cursor::new(encoded_data), &cs);
            let mut out = Vec::new();

            r.read_to_end(&mut out).unwrap();
            assert_eq!(data, out);
        }
    }

    #[test]
    fn test_base64_decoder_roundtrip_standard_1000() {
        test_roundtrip(base64::alphabet::STANDARD, 1000);
    }

    #[test]
    fn test_base64_decoder_roundtrip_crypt_1000() {
        test_roundtrip(base64::alphabet::CRYPT, 1000);
    }

    #[test]
    fn test_base64_decoder_roundtrip_url_safe_1000() {
        test_roundtrip(base64::alphabet::URL_SAFE, 1000);
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
    fn test_base64_decoder_with_end_base() {
        let data = b"TG9yZW0g\n=TG9y\n-----hello";

        let c = Cursor::new(&data[..]);
        let lr = LineReader::new(c);
        let br = Base64Reader::new(lr);
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        let (r, buffer) = reader.into_inner_with_buffer();
        assert!(buffer.is_empty());

        let mut r = r.into_inner().into_inner();
        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 16);
        assert_eq!(&rest, b"=TG9y\n-----hello");
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
        assert!(buffer.is_empty());

        let mut r = r.into_inner().into_inner();
        let mut rest = Vec::new();
        assert_eq!(r.read_to_end(&mut rest).unwrap(), 15);
        assert_eq!(&rest, b"=TG9y-----hello");
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

        // dbg!(std::str::from_utf8(buffer.buf()).unwrap());
        // assert!(buffer.is_empty());

        // let mut r = r.into_inner().into_inner();
        //let mut rest = Vec::new();
        // assert_eq!(r.read_to_end(&mut rest).unwrap(), 10);
        // assert_eq!(&rest, b"=TG9y-----hello");
    }
}
