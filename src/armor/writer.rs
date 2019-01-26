use std::hash::Hasher;
use std::io::Write;

use crc24::Crc24Hasher;

use errors::Result;
use generic_array::typenum::U64;
use line_writer::{LineBreak, LineWriter};
use ser::Serialize;

pub fn write(source: &impl Serialize, typ: &str, writer: &mut impl Write) -> Result<()> {
    let heading = format!("-----BEGIN PGP {} BLOCK-----\n", typ);
    let footer = format!("\n-----END PGP {} BLOCK-----\n", typ);

    writer.write_all(heading.as_bytes())?;

    // TODO: headers
    writer.write_all(&b"\n"[..])?;

    // TODO: avoid buffering
    let mut bytes = Vec::new();
    source.to_writer(&mut bytes)?;
    let mut crc_hasher = Crc24Hasher::init(0x00B7_04CE);
    crc_hasher.write(&bytes);
    let crc = crc_hasher.finish() as u32;

    // write the base64 encoded content
    {
        let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
        let mut enc = base64::write::EncoderWriter::new(&mut line_wrapper, base64::STANDARD);

        enc.write_all(&bytes)?;
    }

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

    writer.write_all(footer.as_bytes())?;

    Ok(())
}
