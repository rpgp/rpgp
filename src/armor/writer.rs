use std::collections::BTreeMap;
use std::hash::Hasher;
use std::io::Write;

use base64::engine::{general_purpose, Engine as _};
use crc24::Crc24Hasher;
use generic_array::typenum::U64;

use crate::armor::BlockType;
use crate::errors::Result;
use crate::line_writer::{LineBreak, LineWriter};
use crate::ser::Serialize;
use crate::util::TeeWriter;

pub fn write(
    source: &impl Serialize,
    typ: BlockType,
    writer: &mut impl Write,
    headers: Option<&BTreeMap<String, String>>,
    include_checksum: bool,
) -> Result<()> {
    // write armor header
    writer.write_all(&b"-----BEGIN "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    // write armor headers
    if let Some(headers) = headers {
        for (key, value) in headers.iter() {
            writer.write_all(key.as_bytes())?;
            writer.write_all(&b": "[..])?;
            writer.write_all(value.as_bytes())?;
            writer.write_all(&b"\n"[..])?;
        }
    }

    writer.write_all(&b"\n"[..])?;
    writer.flush()?;

    // write body
    let mut crc_hasher = include_checksum.then(|| Crc24Hasher::new());
    {
        let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
        let mut enc = ZeroWrapper(base64::write::EncoderWriter::new(
            &mut line_wrapper,
            &general_purpose::STANDARD,
        ));

        if let Some(ref mut crc_hasher) = crc_hasher {
            let mut tee = TeeWriter::new(crc_hasher, &mut enc);
            source.to_writer(&mut tee)?;
        } else {
            source.to_writer(&mut enc)?;
        }
    }

    // write crc
    if let Some(crc_hasher) = crc_hasher {
        writer.write_all(b"=")?;

        let crc = crc_hasher.finish() as u32;
        let crc_buf = [
            // (crc >> 24) as u8,
            (crc >> 16) as u8,
            (crc >> 8) as u8,
            crc as u8,
        ];
        let crc_enc = general_purpose::STANDARD.encode(crc_buf);

        writer.write_all(crc_enc.as_bytes())?;
        writer.write_all(&b"\n"[..])?;
    }

    // write footer
    writer.write_all(&b"-----END "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    Ok(())
}

/// Wrapper to deal with the special way the base64 encoder works.
/// Otherwise we can't use `write_all`.
///
/// Ref https://github.com/marshallpierce/rust-base64/issues/148
struct ZeroWrapper<W: std::io::Write>(W);

impl<W: std::io::Write> std::io::Write for ZeroWrapper<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::io;

    struct TestSource {
        content: Vec<u8>,
    }

    impl Serialize for TestSource {
        fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
            w.write_all(&self.content).unwrap();
            Ok(())
        }
    }

    impl TestSource {
        pub fn new(content: Vec<u8>) -> Self {
            TestSource { content }
        }
    }

    #[test]
    fn writes_no_doubleline() {
        let rng = &mut XorShiftRng::seed_from_u64(0);

        for i in 2..1024 {
            let buf: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let source = TestSource::new(buf);

            let mut dest = Vec::new();

            write(&source, BlockType::Message, &mut dest, None, true).unwrap();

            let dest_str = std::str::from_utf8(&dest).unwrap();
            let lines = dest_str.lines().collect::<Vec<_>>();

            assert_eq!(lines[0], "-----BEGIN PGP MESSAGE-----");
            assert!(
                !lines[lines.len() - 3].is_empty(),
                "last line must not be empty"
            );
            assert_eq!(
                lines[lines.len() - 2].len(),
                5,
                "invalid checksum line: '{}'",
                lines[lines.len() - 2]
            );
            assert_eq!(lines[lines.len() - 1], "-----END PGP MESSAGE-----");
        }
    }

    #[test]
    fn writes_no_checksum() {
        let mut rng = XorShiftRng::seed_from_u64(0);

        for i in 2..1024 {
            let buf: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let source = TestSource::new(buf);

            let mut dest = Vec::new();
            write(&source, BlockType::Message, &mut dest, None, false).unwrap();

            let dest_str = std::str::from_utf8(&dest).unwrap();
            let lines = dest_str.lines().collect::<Vec<_>>();

            assert_eq!(lines[0], "-----BEGIN PGP MESSAGE-----");
            assert!(
                !lines[lines.len() - 3].is_empty(),
                "last line must not be empty"
            );
            assert_eq!(lines[lines.len() - 1], "-----END PGP MESSAGE-----");
        }
    }
}
