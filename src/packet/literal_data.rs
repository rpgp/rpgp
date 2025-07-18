use std::io::{self, BufRead};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(test)]
use proptest::prelude::*;

use crate::{
    errors::{ensure, Result},
    line_writer::LineBreak,
    normalize_lines::{normalize_lines, NormalizedReader},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag},
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
    created: DateTime<Utc>,
}

impl LiteralDataHeader {
    pub fn new(mode: DataMode) -> Self {
        Self {
            mode,
            file_name: "".into(),
            created: std::time::UNIX_EPOCH.into(),
        }
    }

    pub fn mode(&self) -> DataMode {
        self.mode
    }

    pub fn file_name(&self) -> &Bytes {
        &self.file_name
    }

    pub fn created(&self) -> DateTime<Utc> {
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
        let created = r.read_be_u32()?;
        let created = Utc
            .timestamp_opt(created.into(), 0)
            .single()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid created field"))?;

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
            created: Utc::now().trunc_subsecs(0),
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
            created: Utc::now().trunc_subsecs(0),
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
        writer.write_u32::<BigEndian>(self.created.timestamp().try_into()?)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1 + 1;
        sum += self.file_name.len();
        sum += 4;
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

#[allow(clippy::large_enum_variant)]
pub(crate) enum MaybeNormalizedReader<R: io::Read> {
    Normalized(NormalizedReader<R>),
    Raw(R),
}

impl<R: io::Read> MaybeNormalizedReader<R> {
    pub(crate) fn into_inner(self) -> R {
        match self {
            Self::Normalized(s) => s.into_inner(),
            Self::Raw(s) => s,
        }
    }
}

impl<R: io::Read> io::Read for MaybeNormalizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Normalized(r) => r.read(buf),
            Self::Raw(r) => r.read(buf),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum LiteralDataGenerator<R: io::Read> {
    Fixed(LiteralDataFixedGenerator<MaybeNormalizedReader<R>>),
    Partial(LiteralDataPartialGenerator<MaybeNormalizedReader<R>>),
}

impl<R: io::Read> LiteralDataGenerator<R> {
    pub(crate) fn new(
        header: LiteralDataHeader,
        source: R,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        let source = if header.mode == DataMode::Utf8 {
            MaybeNormalizedReader::Normalized(NormalizedReader::new(source, LineBreak::Crlf))
        } else {
            MaybeNormalizedReader::Raw(source)
        };

        Self::from_normalized(header, source, source_len, chunk_size)
    }

    pub(crate) fn from_normalized(
        header: LiteralDataHeader,
        source: MaybeNormalizedReader<R>,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        match source_len {
            Some(source_len) => {
                let gen = LiteralDataFixedGenerator::new(header, source, source_len)?;
                Ok(Self::Fixed(gen))
            }
            None => {
                let gen = LiteralDataPartialGenerator::new(header, source, chunk_size)?;
                Ok(Self::Partial(gen))
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
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        normalize_lines::normalize_lines,
        packet::Packet,
        util::test::{check_strings, random_string, ChaosReader},
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
            any::<(DataMode, Vec<u8>, u32)>()
                .prop_map(|(mode, file_name, created)| {
                    let created = chrono::Utc
                        .timestamp_opt(created as i64, 0)
                        .single()
                        .expect("invalid time");
                    LiteralDataHeader {
                        mode,
                        file_name: file_name.into(),
                        created,
                    }
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
                created: Utc::now().trunc_subsecs(0),
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
                created: Utc::now().trunc_subsecs(0),
            };

            let s = random_string(&mut rng, file_size);
            let mut generator = LiteralDataGenerator::new(
                header.clone(),
                ChaosReader::new(rng.clone(), s.clone()),
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
