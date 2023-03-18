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

    // write body
    let mut crc_hasher = Crc24Hasher::init(0x00B7_04CE);
    {
        let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
        let mut enc =
            base64::write::EncoderWriter::new(&mut line_wrapper, &general_purpose::STANDARD);

        let mut tee = TeeWriter::new(&mut crc_hasher, &mut enc);
        source.to_writer(&mut tee)?;
    }

    let crc = crc_hasher.finish() as u32;

    // write crc
    writer.write_all(b"=")?;

    let crc_buf = [
        // (crc >> 24) as u8,
        (crc >> 16) as u8,
        (crc >> 8) as u8,
        crc as u8,
    ];
    let crc_enc = general_purpose::STANDARD.encode(crc_buf);

    writer.write_all(crc_enc.as_bytes())?;

    // write footer
    writer.write_all(&b"\n-----END "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    Ok(())
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
            w.write_all(&self.content)?;
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
        let rng = &mut XorShiftRng::from_seed([
            0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
        ]);

        for i in 2..1024 {
            let buf: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let source = TestSource::new(buf);

            let mut dest = Vec::with_capacity(2 * i);

            write(&source, BlockType::Message, &mut dest, None).unwrap();

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
}
