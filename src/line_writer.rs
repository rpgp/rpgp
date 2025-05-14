//! # Line writer module

use std::io;

use cipher::{
    array::{Array, ArraySize},
    typenum::{Sum, Unsigned, U2},
};

const CRLF: [u8; 2] = [b'\r', b'\n'];
const CR: [u8; 1] = [b'\r'];
const LF: [u8; 1] = [b'\n'];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LineBreak {
    Crlf,
    Lf,
    Cr,
}

impl AsRef<[u8]> for LineBreak {
    fn as_ref(&self) -> &[u8] {
        match self {
            LineBreak::Crlf => &CRLF[..],
            LineBreak::Lf => &LF[..],
            LineBreak::Cr => &CR[..],
        }
    }
}

/// A `Write` implementation that splits any written bytes into the given length lines.
///
///
/// # Panics
///
/// Calling `write()` after `finish()` is invalid and will panic.
pub struct LineWriter<'a, W, N>
where
    W: io::Write,
    N: Unsigned + ArraySize,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArraySize,
{
    /// Which kind of line break to insert.
    line_break: LineBreak,
    /// Where encoded data is written to.
    w: &'a mut W,
    /// Holds a partial chunk, if any, after the last `write()`, so that we may then fill the chunk
    /// with the next `write()`, write it, then proceed with the rest of the input normally.
    extra: Array<u8, N>,
    /// How much of `extra` is occupied, in `[0, N]`.
    extra_len: usize,
    buffer: Array<u8, Sum<N, U2>>,
    /// True iff partial last chunk has been written.
    finished: bool,
    /// panic safety: don't write again in destructor if writer panicked while we were writing to it
    panicked: bool,
}

impl<'a, W, N> LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArraySize,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArraySize,
{
    /// Creates a new encoder around an existing writer.
    pub fn new(w: &'a mut W, line_break: LineBreak) -> Self {
        LineWriter {
            line_break,
            w,
            extra: Default::default(),
            buffer: Default::default(),
            extra_len: 0,
            finished: false,
            panicked: false,
        }
    }

    /// Write all remaining buffered data.
    ///
    /// Once this succeeds, no further writes can be performed.
    ///
    /// # Errors
    ///
    /// Assuming the wrapped writer obeys the `Write` contract, if this returns `Err`, no data was
    /// written, and `finish()` may be retried if appropriate for the type of error, etc.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        };

        if self.extra_len > 0 {
            self.panicked = true;
            self.w.write_all(&self.extra[..self.extra_len])?;
            self.w.write_all(self.line_break.as_ref())?;
            self.panicked = false;
            // write succeeded, do not write the encoding of extra again if finish() is retried
            self.extra_len = 0;
        }

        self.finished = true;
        Ok(())
    }
}

impl<'a, W, N> io::Write for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArraySize,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArraySize,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.finished {
            panic!("Cannot write more after calling finish()");
        }

        if input.is_empty() {
            return Ok(0);
        }

        // The contract of `Write::write` places some constraints on this implementation:
        // - a call to `write()` represents at most one call to a wrapped `Write`, so we can't
        // iterate over the input and encode multiple chunks.
        // - Errors mean that "no bytes were written to this writer", so we need to reset the
        // internal state to what it was before the error occurred

        let sl = N::to_usize();
        let line_break = self.line_break.as_ref();

        let orig_extra_len = self.extra_len;

        // process leftover stuff from last write
        if self.extra_len + input.len() < sl {
            // still not enough
            self.extra_len += input.len();
            self.extra[orig_extra_len..self.extra_len].copy_from_slice(input);
            Ok(input.len())
        } else {
            let mut buffer_pos = 0;
            let mut input_pos = 0;

            if self.extra_len > 0 {
                let copied = ::std::cmp::min(orig_extra_len, self.buffer.len());
                self.buffer[buffer_pos..buffer_pos + copied].copy_from_slice(&self.extra[..copied]);
                self.extra_len -= copied;
                buffer_pos += copied;
            }

            if buffer_pos < sl {
                let missing = ::std::cmp::min(sl - buffer_pos, input.len() - input_pos);

                self.buffer[buffer_pos..buffer_pos + missing]
                    .copy_from_slice(&input[input_pos..input_pos + missing]);

                buffer_pos += missing;
                input_pos += missing;
            }

            // still not enough
            if buffer_pos < sl {
                return Ok(input_pos);
            }

            // insert line break
            self.buffer[buffer_pos..buffer_pos + line_break.len()].copy_from_slice(line_break);
            buffer_pos += line_break.len();

            self.panicked = true;
            let r = self.w.write_all(&self.buffer[..buffer_pos]);
            self.panicked = false;

            match r {
                Ok(_) => Ok(input_pos),
                Err(err) => {
                    // in case we filled and encoded `extra`, reset extra_len
                    self.extra_len = orig_extra_len;
                    Err(err)
                }
            }
        }
    }

    /// Because this is usually treated as OK to call multiple times, it will *not* flush any
    /// incomplete chunks of input or write padding.
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<'a, W, N> Drop for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArraySize,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArraySize,
{
    fn drop(&mut self) {
        if !self.panicked {
            // like `BufWriter`, ignore errors during drop
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Write;

    use base64::engine::general_purpose;
    use cipher::array::typenum::{self, U10};

    use super::*;

    /// The same as the std lib, but doesn't choke on write 0. This is a hack, to be compatible with
    /// rust-base64.
    fn write_all(writer: &mut impl io::Write, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match writer.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[test]
    fn simple_writes() {
        let mut buf = Vec::new();

        {
            let mut w = LineWriter::<_, U10>::new(&mut buf, LineBreak::Crlf);

            // short write
            assert_eq!(w.write(&[0, 1, 2, 3]).unwrap(), 4);
            assert_eq!(w.write(&[4, 5, 6, 7]).unwrap(), 4);
            assert_eq!(w.write(&[8, 9, 10, 11]).unwrap(), 2);
            assert_eq!(w.write(&[10, 11]).unwrap(), 2);

            // writer dropped, should flush now
        }

        assert_eq!(
            &buf[..],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, b'\r', b'\n', 10, 11, b'\r', b'\n'][..]
        );
    }

    macro_rules! test_len {
        ( $name:ident, $len:ty ) => {
            #[test]
            fn $name() {
                use rand::{Rng, SeedableRng};
                use rand_xorshift::XorShiftRng;

                let rng = &mut XorShiftRng::from_seed([
                    0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
                ]);
                let mut buf = Vec::new();

                let mut list = Vec::new();
                {
                    let mut w = LineWriter::<_, $len>::new(&mut buf, LineBreak::Crlf);
                    for i in 0..100 {
                        let data = (0..i).map(|_| rng.random()).collect::<Vec<_>>();
                        w.write_all(&data).unwrap();
                        list.extend(&data);
                    }
                }

                let len = <$len as typenum::Unsigned>::to_usize();
                let mut expected: Vec<u8> = list.chunks(len).fold(Vec::new(), |mut acc, line| {
                    acc.extend(line);

                    if line.len() == len {
                        acc.push(b'\r');
                        acc.push(b'\n');
                    }
                    acc
                });

                if expected.len() % len != 0 {
                    expected.push(b'\r');
                    expected.push(b'\n');
                }

                assert_eq!(&buf[..], &expected[..]);
            }
        };
    }

    test_len!(test_break_line_len_1, typenum::U1);
    test_len!(test_break_line_len_2, typenum::U2);
    test_len!(test_break_line_len_10, typenum::U10);
    test_len!(test_break_line_len_74, typenum::U74);
    test_len!(test_break_line_len_100, typenum::U100);
    // test_len!(test_break_line_len_256, typenum::U256);

    #[test]
    fn test_key_roundtrip() {
        let content = hex::decode("99010d04583c17af010800b9552ff9f4dae0e66c3ec0402793fbe2d02188f8ae6b1939b202bbb2fda892e2461f5098843eafc965809e350f464db24de4cf858afd5b870eb17847e5e05002fc0d14a37f5fbd448b247d95fbc953dc6c57b7c291631f0cbe8b6fa0a886d4346f827c11875aa26d7ebe86d25a84fc070d5894b85cf465e10f5a20b0ba830e10b9a24ecb845596d0b2fd3c07008ecc873733cb3add3b7030251ef8c061a9f46312eebf1adee68ae1865455c1f7a6a8d8ef6ed47b11edc523815429e89c062e02088a38f2d7aeccb3e7ca65eb6a03db73bb50b5480b4d622aa6014a2a186d581234bba00a6800a9870fe2c608c50f83977a6e1c3e3721e30c015624462fde41b70011010001b43554657374204b65792028646f206e6f742075736529203c61757468656e7469636174652d6f6e6c79406578616d706c652e6f72673e89014e041301080038162104927ef377fd1a1b6f795e40c02a87917d8ffba49f0502583c17af021b01050b09080702061508090a0b020416020301021e01021780000a09102a87917d8ffba49f7ecc07fd1556649c309608d638dbe448477e9fab69751acf0a7ccb17acd5ed7d83ed2ea8a83fc7f3d8b1342e8b9d4ac64c2d5ca0a273c6d190317485075dc15d52a3eb133b387c4c91e3169e392c6e8b643fbbafbd6e2ede8a5618cd53515a4bb2c764eb4506448cc5cc9ee25c5a9b466d15acfe2a5151904759f2e5dae74b97ed134482fb8678b4eb15421dbc04e6ccdc2e8cb3cef228c065400d716a786ee7b72eee44d64d003f9958c1f6274beca599544958bbcf55728330c8dd4e3648c26656a9d19880ac07740b23c36ce27c565cedb3f1f85e48572b3fe2c0718dd6e898272c2cefcaea20c675a67787f3af5881dc4d87732fecaf4720439c2dbac79046199396b9010d04583c17d9010800b4a71b058ac8aa1ddc453ab2663331c38f7645542815ac189a9af56d0e07a615469d3e08849650e03026d49259423cf00d089931cd700fd3a6e940bf83c81406e142a4b0a86f00738c7e1a9ff1b709f6bccc6cf900d0113a8e62e53d63be0a05105755b9efc6a4098c362c73fb422d40187d8e2382e88624d72caffceb13cec8fa0079c7d17883a46a1336471ab5be8cbb555c5d330d7fadb43318fa73b584edac312fa3302886bb5d04a05da3be2676c1fb94b3cf5c19d598659c3a7728ebab95f71721b662ac46aa9910726fe576d438f789c5ce2448f54546f254da814bcae1c35ee44b171e870ffa6403167a10e68573bdf155549274b431ff8e2418b6270011010001890136041801080020162104927ef377fd1a1b6f795e40c02a87917d8ffba49f0502583c17d9021b20000a09102a87917d8ffba49fac6b07ff7928f1c4082501da2517d94ad3bd2e566320ab81853ea27746a24f5058f010515260b5e48802e73065c34a639f3ea090e1cf8f5b0ba6161282cf83175430fcc7a9a2f59f87944c0831a0a7724ad24ee4393a0c0effabe4873e3639c80c6775909d67cd54cf236cd3fdbd7d6fae83de1cb15a3c6cbd28930cd19fe19422087b22bf6bdd335a54f950c7d1a2a35045b63f8a261d9a9bdfebd23d3e86c655ba3feda8594ee98f5b08e218eced3577aea39514680555c4c40160aa76c37c22976b07cd87d37d851233287ea14171e17973585ddb2f3b1a7d169eb8ad61e7e26ebc87229af539cd666d9f484ea62217a593a826fbccf6be43e19453e545f66e543c3f").unwrap();

        // sanit check, ensure the base64 encoding works as expected
        {
            let mut buf = Vec::new();
            {
                let mut enc =
                    base64::write::EncoderWriter::new(&mut buf, &general_purpose::STANDARD);
                enc.write_all(&content).unwrap();
            }

            assert_eq!(
                ::std::str::from_utf8(&buf).unwrap(),
                "mQENBFg8F68BCAC5VS/59Nrg5mw+wEAnk/vi0CGI+K5rGTmyAruy/aiS4kYfUJiE\
                 Pq/JZYCeNQ9GTbJN5M+Fiv1bhw6xeEfl4FAC/A0Uo39fvUSLJH2V+8lT3GxXt8KR\
                 Yx8MvotvoKiG1DRvgnwRh1qibX6+htJahPwHDViUuFz0ZeEPWiCwuoMOELmiTsuE\
                 VZbQsv08BwCOzIc3M8s63TtwMCUe+MBhqfRjEu6/Gt7miuGGVFXB96ao2O9u1HsR\
                 7cUjgVQp6JwGLgIIijjy167Ms+fKZetqA9tzu1C1SAtNYiqmAUoqGG1YEjS7oApo\
                 AKmHD+LGCMUPg5d6bhw+NyHjDAFWJEYv3kG3ABEBAAG0NVRlc3QgS2V5IChkbyBu\
                 b3QgdXNlKSA8YXV0aGVudGljYXRlLW9ubHlAZXhhbXBsZS5vcmc+iQFOBBMBCAA4\
                 FiEEkn7zd/0aG295XkDAKoeRfY/7pJ8FAlg8F68CGwEFCwkIBwIGFQgJCgsCBBYC\
                 AwECHgECF4AACgkQKoeRfY/7pJ9+zAf9FVZknDCWCNY42+RIR36fq2l1Gs8KfMsX\
                 rNXtfYPtLqioP8fz2LE0LoudSsZMLVygonPG0ZAxdIUHXcFdUqPrEzs4fEyR4xae\
                 OSxui2Q/u6+9bi7eilYYzVNRWkuyx2TrRQZEjMXMnuJcWptGbRWs/ipRUZBHWfLl\
                 2udLl+0TRIL7hni06xVCHbwE5szcLoyzzvIowGVADXFqeG7nty7uRNZNAD+ZWMH2\
                 J0vspZlUSVi7z1VygzDI3U42SMJmVqnRmICsB3QLI8Ns4nxWXO2z8fheSFcrP+LA\
                 cY3W6JgnLCzvyuogxnWmd4fzr1iB3E2Hcy/sr0cgQ5wtuseQRhmTlrkBDQRYPBfZ\
                 AQgAtKcbBYrIqh3cRTqyZjMxw492RVQoFawYmpr1bQ4HphVGnT4IhJZQ4DAm1JJZ\
                 QjzwDQiZMc1wD9Om6UC/g8gUBuFCpLCobwBzjH4an/G3Cfa8zGz5ANAROo5i5T1j\
                 vgoFEFdVue/GpAmMNixz+0ItQBh9jiOC6IYk1yyv/OsTzsj6AHnH0XiDpGoTNkca\
                 tb6Mu1VcXTMNf620Mxj6c7WE7awxL6MwKIa7XQSgXaO+JnbB+5Szz1wZ1ZhlnDp3\
                 KOurlfcXIbZirEaqmRByb+V21Dj3icXOJEj1RUbyVNqBS8rhw17kSxcehw/6ZAMW\
                 ehDmhXO98VVUknS0Mf+OJBi2JwARAQABiQE2BBgBCAAgFiEEkn7zd/0aG295XkDA\
                 KoeRfY/7pJ8FAlg8F9kCGyAACgkQKoeRfY/7pJ+sawf/eSjxxAglAdolF9lK070u\
                 VmMgq4GFPqJ3RqJPUFjwEFFSYLXkiALnMGXDSmOfPqCQ4c+PWwumFhKCz4MXVDD8\
                 x6mi9Z+HlEwIMaCnckrSTuQ5OgwO/6vkhz42OcgMZ3WQnWfNVM8jbNP9vX1vroPe\
                 HLFaPGy9KJMM0Z/hlCIIeyK/a90zWlT5UMfRoqNQRbY/iiYdmpvf69I9PobGVbo/\
                 7ahZTumPWwjiGOztNXeuo5UUaAVVxMQBYKp2w3wil2sHzYfTfYUSMyh+oUFx4Xlz\
                 WF3bLzsafRaeuK1h5+JuvIcimvU5zWZtn0hOpiIXpZOoJvvM9r5D4ZRT5UX2blQ8\
                 Pw==",
            );
        }

        let mut buf = Vec::new();
        {
            let mut line_wrapper = LineWriter::<_, typenum::U64>::new(&mut buf, LineBreak::Lf);
            let mut enc =
                base64::write::EncoderWriter::new(&mut line_wrapper, &general_purpose::STANDARD);
            write_all(&mut enc, &content).unwrap();
        }

        assert_eq!(
            ::std::str::from_utf8(&buf).unwrap(),
            "mQENBFg8F68BCAC5VS/59Nrg5mw+wEAnk/vi0CGI+K5rGTmyAruy/aiS4kYfUJiE\n\
             Pq/JZYCeNQ9GTbJN5M+Fiv1bhw6xeEfl4FAC/A0Uo39fvUSLJH2V+8lT3GxXt8KR\n\
             Yx8MvotvoKiG1DRvgnwRh1qibX6+htJahPwHDViUuFz0ZeEPWiCwuoMOELmiTsuE\n\
             VZbQsv08BwCOzIc3M8s63TtwMCUe+MBhqfRjEu6/Gt7miuGGVFXB96ao2O9u1HsR\n\
             7cUjgVQp6JwGLgIIijjy167Ms+fKZetqA9tzu1C1SAtNYiqmAUoqGG1YEjS7oApo\n\
             AKmHD+LGCMUPg5d6bhw+NyHjDAFWJEYv3kG3ABEBAAG0NVRlc3QgS2V5IChkbyBu\n\
             b3QgdXNlKSA8YXV0aGVudGljYXRlLW9ubHlAZXhhbXBsZS5vcmc+iQFOBBMBCAA4\n\
             FiEEkn7zd/0aG295XkDAKoeRfY/7pJ8FAlg8F68CGwEFCwkIBwIGFQgJCgsCBBYC\n\
             AwECHgECF4AACgkQKoeRfY/7pJ9+zAf9FVZknDCWCNY42+RIR36fq2l1Gs8KfMsX\n\
             rNXtfYPtLqioP8fz2LE0LoudSsZMLVygonPG0ZAxdIUHXcFdUqPrEzs4fEyR4xae\n\
             OSxui2Q/u6+9bi7eilYYzVNRWkuyx2TrRQZEjMXMnuJcWptGbRWs/ipRUZBHWfLl\n\
             2udLl+0TRIL7hni06xVCHbwE5szcLoyzzvIowGVADXFqeG7nty7uRNZNAD+ZWMH2\n\
             J0vspZlUSVi7z1VygzDI3U42SMJmVqnRmICsB3QLI8Ns4nxWXO2z8fheSFcrP+LA\n\
             cY3W6JgnLCzvyuogxnWmd4fzr1iB3E2Hcy/sr0cgQ5wtuseQRhmTlrkBDQRYPBfZ\n\
             AQgAtKcbBYrIqh3cRTqyZjMxw492RVQoFawYmpr1bQ4HphVGnT4IhJZQ4DAm1JJZ\n\
             QjzwDQiZMc1wD9Om6UC/g8gUBuFCpLCobwBzjH4an/G3Cfa8zGz5ANAROo5i5T1j\n\
             vgoFEFdVue/GpAmMNixz+0ItQBh9jiOC6IYk1yyv/OsTzsj6AHnH0XiDpGoTNkca\n\
             tb6Mu1VcXTMNf620Mxj6c7WE7awxL6MwKIa7XQSgXaO+JnbB+5Szz1wZ1ZhlnDp3\n\
             KOurlfcXIbZirEaqmRByb+V21Dj3icXOJEj1RUbyVNqBS8rhw17kSxcehw/6ZAMW\n\
             ehDmhXO98VVUknS0Mf+OJBi2JwARAQABiQE2BBgBCAAgFiEEkn7zd/0aG295XkDA\n\
             KoeRfY/7pJ8FAlg8F9kCGyAACgkQKoeRfY/7pJ+sawf/eSjxxAglAdolF9lK070u\n\
             VmMgq4GFPqJ3RqJPUFjwEFFSYLXkiALnMGXDSmOfPqCQ4c+PWwumFhKCz4MXVDD8\n\
             x6mi9Z+HlEwIMaCnckrSTuQ5OgwO/6vkhz42OcgMZ3WQnWfNVM8jbNP9vX1vroPe\n\
             HLFaPGy9KJMM0Z/hlCIIeyK/a90zWlT5UMfRoqNQRbY/iiYdmpvf69I9PobGVbo/\n\
             7ahZTumPWwjiGOztNXeuo5UUaAVVxMQBYKp2w3wil2sHzYfTfYUSMyh+oUFx4Xlz\n\
             WF3bLzsafRaeuK1h5+JuvIcimvU5zWZtn0hOpiIXpZOoJvvM9r5D4ZRT5UX2blQ8\n\
             Pw==\n"
        );
    }
}
