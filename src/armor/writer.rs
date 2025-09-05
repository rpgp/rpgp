use std::{hash::Hasher, io::Write};

use base64::engine::{general_purpose, Engine as _};
use cipher::typenum::U64;
use crc24::Crc24Hasher;

use super::Headers;
use crate::{
    armor::BlockType,
    errors::Result,
    line_writer::{LineBreak, LineWriter},
    ser::Serialize,
    util::TeeWriter,
};

pub fn write(
    source: &impl Serialize,
    typ: BlockType,
    writer: &mut impl Write,
    headers: Option<&Headers>,
    include_checksum: bool,
) -> Result<()> {
    write_header(writer, typ, headers)?;

    // write body
    let mut crc_hasher = include_checksum.then(Crc24Hasher::new);

    write_body(writer, source, crc_hasher.as_mut())?;

    write_footer(writer, typ, crc_hasher)?;

    Ok(())
}

pub(crate) fn write_header(
    writer: &mut impl Write,
    typ: BlockType,
    headers: Option<&Headers>,
) -> Result<()> {
    // write armor header
    writer.write_all(&b"-----BEGIN "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    // write armor headers
    if let Some(headers) = headers {
        for (key, values) in headers.iter() {
            for value in values {
                writer.write_all(key.as_bytes())?;
                writer.write_all(&b": "[..])?;
                writer.write_all(value.as_bytes())?;
                writer.write_all(&b"\n"[..])?;
            }
        }
    }

    writer.write_all(&b"\n"[..])?;
    writer.flush()?;

    Ok(())
}

fn write_body(
    writer: &mut impl Write,
    source: &impl Serialize,
    crc_hasher: Option<&mut Crc24Hasher>,
) -> Result<()> {
    {
        let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
        let mut enc = Base64Encoder::new(&mut line_wrapper);

        if let Some(crc_hasher) = crc_hasher {
            let mut tee = TeeWriter::new(crc_hasher, &mut enc);
            source.to_writer(&mut tee)?;
        } else {
            source.to_writer(&mut enc)?;
        }
    }

    Ok(())
}

pub(crate) fn write_footer(
    writer: &mut impl Write,
    typ: BlockType,
    crc_hasher: Option<Crc24Hasher>,
) -> Result<()> {
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
pub(crate) struct Base64Encoder<W: std::io::Write>(
    base64::write::EncoderWriter<'static, general_purpose::GeneralPurpose, W>,
);

impl<W: std::io::Write> Base64Encoder<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self(base64::write::EncoderWriter::new(
            writer,
            &general_purpose::STANDARD,
        ))
    }
}
impl<W: std::io::Write> std::io::Write for Base64Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.0.write(buf) {
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

    use std::io;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use rand_xorshift::XorShiftRng;

    use super::*;
    use crate::util::test::ChaosReader;

    struct TestSource {
        content: Vec<u8>,
    }

    impl Serialize for TestSource {
        fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
            w.write_all(&self.content).unwrap();
            Ok(())
        }
        fn write_len(&self) -> usize {
            self.content.len()
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
            let buf: Vec<u8> = (0..i).map(|_| rng.random()).collect();
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
            let buf: Vec<u8> = (0..i).map(|_| rng.random()).collect();
            let source = TestSource::new(buf);

            let mut dest = Vec::new();
            write(&source, BlockType::Message, &mut dest, None, false).unwrap();

            let dest_str = std::str::from_utf8(&dest).unwrap();
            let lines = dest_str.lines().collect::<Vec<_>>();

            assert_eq!(lines[0], "-----BEGIN PGP MESSAGE-----");
            assert!(
                !lines[lines.len() - 2].is_empty(),
                "last line must not be empty"
            );
            assert_eq!(lines[lines.len() - 1], "-----END PGP MESSAGE-----");
        }
    }

    #[test]
    fn test_base64_encoder() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        for size in 1..=500 {
            // Generate data
            let mut buf = vec![0u8; size];
            rng.fill(&mut buf[..]);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let mut out = Vec::new();
            {
                let mut writer = Base64Encoder::new(&mut out);
                std::io::copy(&mut reader, &mut writer).unwrap();
            }
            let out = std::string::String::from_utf8(out).unwrap();

            let out2 = general_purpose::STANDARD.encode(buf);
            assert_eq!(out, out2);
        }
    }
}
