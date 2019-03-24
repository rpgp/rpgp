use std::collections::BTreeMap;
use std::hash::Hasher;
use std::io::Write;

use crc24::Crc24Hasher;

use armor::BlockType;
use errors::Result;
use generic_array::typenum::U64;
use line_writer::{LineBreak, LineWriter};
use ser::Serialize;
use util::TeeWriter;

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
        let mut enc = base64::write::EncoderWriter::new(&mut line_wrapper, base64::STANDARD);

        let mut tee = TeeWriter::new(&mut crc_hasher, &mut enc);
        source.to_writer(&mut tee)?;
    }

    let crc = crc_hasher.finish() as u32;

    // write crc
    writer.write_all(b"\n=")?;

    let crc_buf = [
        // (crc >> 24) as u8,
        (crc >> 16) as u8,
        (crc >> 8) as u8,
        crc as u8,
    ];
    let crc_enc = base64::encode_config(&crc_buf, base64::STANDARD);

    writer.write_all(crc_enc.as_bytes())?;

    // write footer
    writer.write_all(&b"\n-----END "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    Ok(())
}
