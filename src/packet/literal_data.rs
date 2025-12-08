use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(test)]
use proptest::prelude::*;

use crate::{
    errors::{ensure, Result},
    line_writer::LineBreak,
    normalize_lines::normalize_lines,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag, Timestamp},
    util::fill_buffer,
};

/// Literal Data Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-literal-data-packet-type-id>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct LiteralData {
    packet_header: PacketHeader,
    header: LiteralDataHeader,
    /// Raw data, stored normalized to CRLF line endings, to make signing and verification
    /// simpler.
    #[debug("{}", hex::encode(data))]
    #[cfg_attr(
        test,
        proptest(
            strategy = "any::<Vec<u8>>().prop_map(Into::into)",
            filter = "|d| !d.is_empty()"
        )
    )]
    data: Bytes,
}
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct LiteralDataHeader {
    mode: DataMode,
    /// The filename, may contain non utf-8 bytes
    file_name: Bytes,
    created: Timestamp,
}

impl LiteralDataHeader {
    pub fn new(mode: DataMode) -> Self {
        Self {
            mode,
            file_name: "".into(),
            created: Timestamp::default(),
        }
    }

    pub fn mode(&self) -> DataMode {
        self.mode
    }

    pub fn file_name(&self) -> &Bytes {
        &self.file_name
    }

    pub fn created(&self) -> Timestamp {
        self.created
    }
}

impl LiteralDataHeader {
    pub fn try_from_reader<R: BufRead>(mut r: R) -> io::Result<Self> {
        // Mode
        let mode = r.read_u8().map(DataMode::from)?;

        // Name
        let name_len = r.read_u8()?;
        let file_name = r.take_bytes(name_len.into())?;

        // Created
        let created = r.read_timestamp()?;

        Ok(Self {
            mode,
            file_name: file_name.freeze(),
            created,
        })
    }
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum DataMode {
    Binary = b'b',
    /// Deprecated.
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))]
    Other(u8),
}

impl LiteralData {
    /// Creates a literal data packet from the given string. Normalizes line endings.
    ///
    /// The data length combined with the header information must not be larger than `u32::MAX`.
    pub fn from_str(file_name: impl Into<Bytes>, raw_data: &str) -> Result<Self> {
        let data: Bytes = normalize_lines(raw_data, LineBreak::Crlf)
            .to_string()
            .into();
        let header = LiteralDataHeader {
            mode: DataMode::Utf8,
            file_name: file_name.into(),
            created: Timestamp::now(),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len.try_into()?);

        Ok(LiteralData {
            packet_header,
            header,
            data,
        })
    }

    /// Creates a literal data packet from the given bytes.
    ///
    /// The data length combined with the header information must not be larger than `u32::MAX`.
    pub fn from_bytes(file_name: impl Into<Bytes>, data: Bytes) -> Result<Self> {
        let header = LiteralDataHeader {
            mode: DataMode::Binary,
            file_name: file_name.into(),
            created: Timestamp::now(),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len.try_into()?);

        Ok(LiteralData {
            packet_header,
            header,
            data,
        })
    }

    /// Parses a `LiteralData` packet from the given reader.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        let header = LiteralDataHeader::try_from_reader(&mut data)?;
        let data = data.rest()?;

        Ok(LiteralData {
            packet_header,
            header,
            data: data.freeze(),
        })
    }

    pub fn file_name(&self) -> &Bytes {
        &self.header.file_name
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.header.mode, DataMode::Binary)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    /// Extracts data in to raw data
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    #[inline]
    /// Extracts data as string, returning raw bytes as Err if not valid utf-8 string
    pub fn try_into_string(self) -> Result<String, Bytes> {
        let Self { data, .. } = self;
        match self.header.mode {
            DataMode::Binary => Err(data),
            _ => match std::string::String::from_utf8(Vec::from(data)) {
                Ok(data) => Ok(data),
                Err(error) => Err(error.into_bytes().into()),
            },
        }
    }

    /// Convert the data to a UTF-8 string, if appropriate for the type.
    /// Returns `None` if `mode` is `Binary`, or the data is not valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        match self.header.mode {
            DataMode::Binary => None,
            _ => std::str::from_utf8(&self.data).ok(),
        }
    }
}

impl AsRef<[u8]> for LiteralData {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for LiteralDataHeader {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = &self.file_name;
        writer.write_u8(self.mode.into())?;
        writer.write_u8(name.len().try_into()?)?;
        writer.write_all(name)?;
        self.created.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1 + 1;
        sum += self.file_name.len();
        sum += self.created.write_len();
        sum
    }
}

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.header.to_writer(writer)?;
        // Line endings are stored internally normalized, so we do not need to worry
        // about changing them here.
        writer.write_all(&self.data)?;

        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = self.header.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for LiteralData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

/// A reader that checks if literal data packet content is legal.
///
/// For "Binary" literals, this passes data through and checks nothing.
/// For "Utf8" literals, this checks that line-endings are CR+LF, and the data is valid UTF-8.
pub(crate) enum LiteralCheckingReader<R: io::Read> {
    Utf8Checking(CrLfCheckReader<Utf8CheckReader<R>>),
    BinaryRaw(R),
}

impl<R: io::Read> LiteralCheckingReader<R> {
    pub(crate) fn into_inner(self) -> R {
        match self {
            Self::Utf8Checking(s) => s.into_inner().into_inner(),
            Self::BinaryRaw(s) => s,
        }
    }
}

impl<R: io::Read> io::Read for LiteralCheckingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Utf8Checking(r) => r.read(buf),
            Self::BinaryRaw(r) => r.read(buf),
        }
    }
}

/// Wrapping reader that checks that all line endings are CR+LF.
///
/// Any other line endings in the input stream are rejected with an `io::Error`.
pub(crate) struct CrLfCheckReader<R>
where
    R: io::Read,
{
    source: R,
    last_was_cr: bool,
}

impl<R: io::Read> CrLfCheckReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            last_was_cr: false,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for CrLfCheckReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.source.read(buf)?;

        // Reading is done, no more checks required
        if len == 0 {
            return Ok(0);
        }

        // Check the body of this read for any illegal linebreaks

        // Skip the first byte if it is a matching LF
        let mut pos = if self.last_was_cr && buf[0] == b'\n' {
            1
        } else {
            0
        };

        // Inspect data from the start until the second-to-last byte
        // (because we want to look ahead one byte, if "pos" is a CR)
        while pos < len - 1 {
            // A standalone linefeed is not ok
            if buf[pos] == b'\n' {
                return Err(io::Error::other(
                    "Illegal line ending (LF without preceding CR)",
                ));
            }

            // Skip CR followed by LF in one go
            if buf[pos] == b'\r' && buf[pos + 1] == b'\n' {
                pos += 2;
            } else {
                pos += 1;
            }
        }

        // If `buf` doesn't end in CR+LF, then `pos` now points at the very last byte.
        // In this case, if the last byte is an LF, it is un-matched, and we throw an error.
        if pos < len && buf[pos] == b'\n' {
            return Err(io::Error::other(
                "Illegal line ending (LF without preceding CR)",
            ));
        }

        // Remember if the last character is a CR.
        // If so, we'll allow a matching LF at the start of the next read.
        self.last_was_cr = buf[len - 1] == b'\r';

        Ok(len)
    }
}

/// Wrapping reader that checks that the input data is valid UTF-8.
///
/// Non-UTF-8 data in the input stream is rejected with an `io::Error`.
pub(crate) struct Utf8CheckReader<R>
where
    R: io::Read,
{
    source: R,

    // Overhang bytes from the last read, if any.
    // If this is `Some`, it contains bytes that we'll prepend and check with the next read.
    rest: Option<Vec<u8>>,
}

impl<R: io::Read> Utf8CheckReader<R> {
    fn new(source: R) -> Self {
        Self { source, rest: None }
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for Utf8CheckReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Checks if `data` contains valid utf-8 and returns up to 3 bytes of overhang, which
        // might add up to a valid codepoint with more data in the following read.
        // Errors if `data` is definitely not UTF-8.
        fn check_utf8(data: &[u8]) -> Result<Option<Vec<u8>>, io::Error> {
            match std::str::from_utf8(data) {
                Ok(_) => Ok(None),
                Err(err) => {
                    let valid_up_to = err.valid_up_to();

                    // handle the remaining data, which may be a fragment of UTF-8 that will be
                    // completed in the next read
                    let rest = &data[valid_up_to..];

                    match rest.len() {
                        0 => Ok(None),
                        1..=3 => Ok(Some(Vec::from(rest))),

                        // 3 bytes is the longest possibly legal intermediate fragment of UTF-8 data.
                        // If `rest` is longer, then the data is definitely not valid UTF-8.
                        4.. => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid UTF-8 data",
                        )),
                    }
                }
            }
        }

        let len = self.source.read(buf)?;

        if len == 0 {
            // We reached the end of the input stream

            // If the UTF-8 parsing seems to be stuck mid-codepoint, we error
            if self.rest.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 data",
                ));
            }

            return Ok(0);
        }

        self.rest = if let Some(mut check) = self.rest.take() {
            // check overhang from last read + the new data from this read
            check.extend_from_slice(&buf[..len]);
            check_utf8(&check)?
        } else {
            // we have no overhang from the last read, just check the data from this read
            check_utf8(&buf[..len])?
        };

        Ok(len)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum LiteralDataGenerator<R: io::Read> {
    Fixed(LiteralDataFixedGenerator<LiteralCheckingReader<R>>),
    Partial(LiteralDataPartialGenerator<LiteralCheckingReader<R>>),
}

impl<R: io::Read> LiteralDataGenerator<R> {
    pub(crate) fn new(
        header: LiteralDataHeader,
        source: R,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        let source = if header.mode == DataMode::Utf8 {
            let utf8 = Utf8CheckReader::new(source);
            let crlf = CrLfCheckReader::new(utf8);

            LiteralCheckingReader::Utf8Checking(crlf)
        } else {
            LiteralCheckingReader::BinaryRaw(source)
        };

        Self::from_normalized(header, source, source_len, chunk_size)
    }

    pub(crate) fn from_normalized(
        header: LiteralDataHeader,
        source: LiteralCheckingReader<R>,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        match source_len {
            Some(source_len) => {
                let genn = LiteralDataFixedGenerator::new(header, source, source_len)?;
                Ok(Self::Fixed(genn))
            }
            None => {
                let genn = LiteralDataPartialGenerator::new(header, source, chunk_size)?;
                Ok(Self::Partial(genn))
            }
        }
    }

    pub(crate) fn len(&self) -> Option<u32> {
        match self {
            Self::Fixed(ref fixed) => Some(fixed.total_len),
            Self::Partial { .. } => None,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        match self {
            Self::Fixed(s) => s.into_inner().into_inner(),
            Self::Partial(s) => s.into_inner().into_inner(),
        }
    }
}

impl<R: io::Read> io::Read for LiteralDataGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self {
            Self::Fixed(ref mut fixed) => fixed.read(buf)?,
            Self::Partial(ref mut partial) => partial.read(buf)?,
        };
        Ok(read)
    }
}

pub(crate) struct LiteralDataFixedGenerator<R: io::Read> {
    /// The serialized packet header
    header: Vec<u8>,
    /// Data source
    source: R,
    /// how many bytes of the header have we written already
    header_written: usize,
    total_len: u32,
}

impl<R: io::Read> LiteralDataFixedGenerator<R> {
    pub(crate) fn new(header: LiteralDataHeader, source: R, source_len: u32) -> Result<Self> {
        let len = source_len + u32::try_from(header.write_len())?;
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);
        let mut serialized_header = Vec::new();
        packet_header.to_writer(&mut serialized_header)?;
        header.to_writer(&mut serialized_header)?;

        let total_len = source_len + u32::try_from(serialized_header.len())?;

        Ok(Self {
            header: serialized_header,
            source,
            header_written: 0,
            total_len,
        })
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for LiteralDataFixedGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let header_bytes_left = self.header.len() - self.header_written;
        if header_bytes_left > 0 {
            // write header
            let to_write = header_bytes_left.min(buf.len());
            buf[..to_write]
                .copy_from_slice(&self.header[self.header_written..self.header_written + to_write]);
            self.header_written += to_write;
            Ok(to_write)
        } else {
            // write source
            self.source.read(buf)
        }
    }
}

pub(crate) struct LiteralDataPartialGenerator<R: io::Read> {
    /// The header
    header: LiteralDataHeader,
    /// Data source
    source: R,
    /// buffer for the individual data
    buffer: Box<[u8]>,
    chunk_size: u32,
    is_done: bool,
    is_first: bool,
    /// Did we emit a (final) fixed packet yet?
    is_fixed_emitted: bool,
    /// Serialized version of the packet being written currently.
    current_packet: BytesMut,
}

impl<R: io::Read> LiteralDataPartialGenerator<R> {
    pub(crate) fn new(header: LiteralDataHeader, source: R, chunk_size: u32) -> Result<Self> {
        ensure!(chunk_size >= 512, "chunk size must be larger than 512");
        ensure!(
            chunk_size.is_power_of_two(),
            "chunk size must be a power of two"
        );
        Ok(Self {
            header,
            source,
            buffer: vec![0u8; chunk_size as usize].into_boxed_slice(),
            chunk_size,
            is_done: false,
            is_first: true,
            is_fixed_emitted: false,
            current_packet: BytesMut::with_capacity(chunk_size as usize),
        })
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for LiteralDataPartialGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.current_packet.has_remaining() {
            if self.is_done && self.is_fixed_emitted {
                return Ok(0);
            }

            let chunk_size = if self.is_first {
                self.chunk_size as usize - self.header.write_len()
            } else {
                self.chunk_size as usize
            };

            let buf_size = match fill_buffer(&mut self.source, &mut self.buffer, Some(chunk_size)) {
                Ok(size) => size,
                Err(err) => {
                    self.is_done = true;
                    return Err(err);
                }
            };

            debug!("read chunk {buf_size} bytes");
            debug_assert!(buf_size <= u32::MAX as usize);

            if buf_size == 0 && self.is_fixed_emitted {
                self.is_done = true;
                return Ok(0);
            }

            let data = &self.buffer[..buf_size];

            let packet_length = if self.is_first && buf_size < chunk_size {
                // all data fits into a single packet
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = (buf_size + self.header.write_len())
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            } else if buf_size == chunk_size {
                // partial
                PacketLength::Partial(self.chunk_size)
            } else {
                // final packet, this can be length 0
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = data
                    .len()
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            };

            let mut writer = std::mem::take(&mut self.current_packet).writer();
            if self.is_first {
                // only the first packet needs the literal data header
                let packet_header = PacketHeader::from_parts(
                    PacketHeaderVersion::New,
                    Tag::LiteralData,
                    packet_length,
                )
                .expect("known construction");
                packet_header
                    .to_writer(&mut writer)
                    .map_err(io::Error::other)?;

                self.header
                    .to_writer(&mut writer)
                    .map_err(io::Error::other)?;

                debug!("first partial packet {packet_header:?}");
                self.is_first = false;
            } else {
                // only length
                packet_length
                    .to_writer_new(&mut writer)
                    .map_err(io::Error::other)?;
                debug!("partial packet {packet_length:?}");
            };

            let mut packet_ser = writer.into_inner();
            packet_ser.extend_from_slice(data);
            self.current_packet = packet_ser;
        }

        let to_write = self.current_packet.remaining().min(buf.len());
        self.current_packet.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use chacha20::ChaCha20Rng;
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::{
        normalize_lines::normalize_lines,
        packet::Packet,
        util::test::{check_strings, random_string, random_utf8_string, ChaosReader},
    };

    #[test]
    fn test_utf8_literal() {
        let slogan = "一门赋予每个人构建可靠且高效软件能力的语言。";
        let literal = LiteralData::from_str("", slogan).unwrap();
        assert!(std::str::from_utf8(&literal.data).unwrap() == slogan);
    }

    impl Arbitrary for LiteralDataHeader {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<(DataMode, Vec<u8>, Timestamp)>()
                .prop_map(|(mode, file_name, created)| LiteralDataHeader {
                    mode,
                    file_name: file_name.into(),
                    created,
                })
                .boxed()
        }
    }

    #[test]
    fn test_literal_data_fixed_generator() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let file_size = 1024 * 14 + 8;
        let mut buf = vec![0u8; file_size];
        rng.fill(&mut buf[..]);

        let packet = LiteralData::from_bytes("hello", buf.to_vec().into()).unwrap();

        let mut generator =
            LiteralDataFixedGenerator::new(packet.header.clone(), &buf[..], file_size as _)
                .unwrap();

        let mut generator_out = Vec::new();
        std::io::copy(&mut generator, &mut generator_out).unwrap();

        let mut packet_out = Vec::new();
        packet.to_writer_with_header(&mut packet_out).unwrap();

        assert_eq!(packet_out, generator_out);

        assert_eq!(packet_out.len(), generator.total_len as usize);
    }

    #[test]
    fn test_literal_data_binary_partial_roundtrip() {
        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let chunk_size = 512;

        let max_file_size = chunk_size * 5 + 100;

        for file_size in 1..=max_file_size {
            println!("size {file_size}");
            let mut buf = vec![0u8; file_size];
            rng.fill(&mut buf[..]);

            let header = LiteralDataHeader {
                file_name: "hello.txt".into(),
                mode: DataMode::Binary,
                created: Timestamp::now(),
            };

            let mut generator =
                LiteralDataGenerator::new(header.clone(), &buf[..], None, chunk_size as u32)
                    .unwrap();

            let mut out = Vec::new();
            std::io::copy(&mut generator, &mut out).unwrap();

            let packets: Vec<_> = crate::packet::many::PacketParser::new(&out[..]).collect();
            assert_eq!(packets.len(), 1, "{:?}", packets);
            let packet = packets[0].as_ref().unwrap();

            assert_eq!(packet.packet_header().tag(), Tag::LiteralData);
            let Packet::LiteralData(data) = packet else {
                panic!("invalid packet: {packet:?}");
            };

            assert_eq!(data.header, header);
            assert_eq!(data.data, buf);
        }
    }

    #[test]
    fn test_literal_data_utf8_partial_roundtrip() {
        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let chunk_size = 512;

        let max_file_size = chunk_size * 5 + 100;

        for file_size in 1..=max_file_size {
            println!("size {file_size}");

            let header = LiteralDataHeader {
                file_name: "hello.txt".into(),
                mode: DataMode::Utf8,
                created: Timestamp::now(),
            };

            let s = random_string(&mut rng, file_size);

            // DataMode::Utf8 only accepts data that uses Crlf line endings
            let s = normalize_lines(&s, LineBreak::Crlf).to_string();

            let mut generator = LiteralDataGenerator::new(
                header.clone(),
                ChaosReader::new(rng.fork(), s.clone()),
                None,
                chunk_size as u32,
            )
            .unwrap();

            let mut out = Vec::new();
            std::io::copy(&mut generator, &mut out).unwrap();

            let packets: Vec<_> = crate::packet::many::PacketParser::new(&out[..]).collect();
            assert_eq!(packets.len(), 1, "{:?}", packets);
            let packet = packets[0].as_ref().unwrap();

            assert_eq!(packet.packet_header().tag(), Tag::LiteralData);
            let Packet::LiteralData(data) = packet else {
                panic!("invalid packet: {packet:?}");
            };

            assert_eq!(data.header, header);
            let normalized_s = normalize_lines(&s, LineBreak::Crlf);
            check_strings(data.as_str().unwrap(), normalized_s);
        }
    }

    #[test]
    fn test_utf8_check_reader() {
        // tests the "ok" case of Utf8CheckReader

        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for len in (1..100_000).step_by(1000) {
            let string = random_utf8_string(&mut rng, len);
            let b: Bytes = Bytes::from(string.clone());

            let cr = ChaosReader::new(&mut rng, b);
            let mut r = Utf8CheckReader::new(cr);

            let mut out = Vec::new();
            let _ = r.read_to_end(&mut out).expect("ok");

            assert_eq!(out, string.as_bytes());
        }
    }

    #[test]
    fn test_utf8_check_reader_bad() {
        // (mostly) tests the "bad" case of Utf8CheckReader

        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for count in 1..10_000 {
            // 10k tests on Vec<u8> of length 0-99
            let len = count % 100;

            let bytes: Vec<u8> = (1..=len).map(|_| rng.random::<u8>()).collect();

            let cr = ChaosReader::new(&mut rng, bytes.clone());
            let mut r = Utf8CheckReader::new(cr);

            let mut out = Vec::new();

            match String::from_utf8(bytes.clone()) {
                Ok(_) => {
                    // the random bytes happen to be valid utf8
                    let _ = r.read_to_end(&mut out).expect("ok");

                    assert_eq!(out, bytes);
                }
                Err(_) => {
                    // the random bytes are not valid utf8
                    let _ = r.read_to_end(&mut out).expect_err("expect error");
                }
            }
        }
    }

    #[test]
    fn test_crlf_check_reader() {
        // tests the "ok" case of CrLfCheckReader

        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for len in (1..100_000).step_by(1000) {
            let string = random_string(&mut rng, len);
            let crlf = normalize_lines(&string, LineBreak::Crlf);

            let b: Bytes = Bytes::from(crlf.to_string());

            let cr = ChaosReader::new(&mut rng, b);
            let mut r = CrLfCheckReader::new(cr);

            let mut out = Vec::new();
            let _ = r.read_to_end(&mut out).expect("ok");

            assert_eq!(out, crlf.as_bytes());
        }
    }

    #[test]
    fn test_crlf_check_reader_bad() {
        // tests the "bad" case of CrLfCheckReader

        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for count in 1..10000 {
            // 10k tests on Unicode strings of length 0-99
            let len = count % 100;

            let string = random_string(&mut rng, len);

            // Our goal in this test is to produce strings in `test` that have "illegal" linebreaks,
            // and to make sure that `CrLfCheckReader` reliably errors for all of them.
            //
            // `string` is a precursor. The `normalize_lines` step below transforms CR+LF in
            // `string` to LF in `test`.
            //
            // Test strings for this case need to contain "freestanding" LF
            // (which do not form CR+LF pairs).
            //
            // Here we skip all `string` that won't lead to illegal line endings in `test`:
            //
            // So we reject `string` if it contains no LF at all, or if it contains CR+CR+LF
            // segments (those would get transformed into "legal" CR+LF pairs).
            if !string.contains('\n') || string.contains("\r\r\n") {
                // Statistical observation: This filter skips ~60% of the random `string`s
                continue;
            }

            // transform "CR+LF" to "just LF", then expect failure
            let test = normalize_lines(&string, LineBreak::Lf);

            let b: Bytes = Bytes::from(test.to_string());

            let cr = ChaosReader::new(&mut rng, b);
            let mut r = CrLfCheckReader::new(cr);

            let mut out = Vec::new();
            let _ = r.read_to_end(&mut out).expect_err("should error");
        }
    }

    proptest! {
        #[test]
        fn write_len(packet: LiteralData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(packet: LiteralData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = LiteralData::try_from_reader(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
