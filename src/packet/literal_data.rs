use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::errors::Result;
use crate::line_writer::LineBreak;
use crate::normalize_lines::Normalized;
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{PacketHeaderVersion, PacketLength, Tag};

#[cfg(test)]
use proptest::prelude::*;

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
    pub mode: DataMode,
    /// The filename, may contain non utf-8 bytes
    pub file_name: Bytes,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',

    #[num_enum(catch_all)]
    #[cfg_attr(test, proptest(skip))]
    Other(u8),
}

impl LiteralData {
    /// Creates a literal data packet from the given string. Normalizes line endings.
    pub fn from_str(file_name: impl Into<Bytes>, raw_data: &str) -> Self {
        let data: Bytes = Normalized::new(raw_data.bytes(), LineBreak::Crlf).collect();
        let header = LiteralDataHeader {
            mode: DataMode::Utf8,
            file_name: file_name.into(),
            created: Utc::now().trunc_subsecs(0),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);

        LiteralData {
            packet_header,
            header,
            data,
        }
    }

    /// Creates a literal data packet from the given bytes.
    pub fn from_bytes(file_name: impl Into<Bytes>, data: Bytes) -> Self {
        let header = LiteralDataHeader {
            mode: DataMode::Binary,
            file_name: file_name.into(),
            created: Utc::now().trunc_subsecs(0),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);

        LiteralData {
            packet_header,
            header,
            data,
        }
    }

    /// Parses a `LiteralData` packet from the given buf.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        // Mode
        let mode = data.read_u8().map(DataMode::from)?;

        // Name
        let name_len = data.read_u8()?;
        let name = data.read_take(name_len.into())?;

        // Created
        let created = data.read_be_u32()?;
        let created = Utc
            .timestamp_opt(created.into(), 0)
            .single()
            .ok_or_else(|| format_err!("invalid created field"))?;

        let data = data.rest();

        Ok(LiteralData {
            packet_header,
            header: LiteralDataHeader {
                mode,
                created,
                file_name: name,
            },
            data,
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
        match self.header.mode {
            DataMode::Binary => Err(self.data),
            _ => match std::str::from_utf8(&self.data) {
                Ok(data) => Ok(data.to_string()),
                Err(_error) => Err(self.data),
            },
        }
    }

    /// Convert the data to a UTF-8 string, if appropriate for the type.
    /// Returns `None` if `mode` is `Binary`, or the data is not valid UTF-8.
    pub fn to_string(&self) -> Option<String> {
        match self.header.mode {
            DataMode::Binary => None,
            _ => std::str::from_utf8(&self.data).map(str::to_owned).ok(),
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

pub(crate) enum LiteralDataGenerator<R: io::Read> {
    Fixed(LiteralDataFixedGenerator<R>),
    Partial {
        gen: LiteralDataPartialGenerator<R>,
        /// Serialized version of the packet being written currently.
        current_packet: Option<Bytes>,
        /// Currently writing the first packet?
        is_first: bool,
    },
}

impl<R: io::Read> LiteralDataGenerator<R> {
    pub(crate) fn new(
        header: LiteralDataHeader,
        source: R,
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
                Ok(Self::Partial {
                    gen,
                    current_packet: None,
                    is_first: true,
                })
            }
        }
    }

    pub(crate) fn len(&self) -> Option<u32> {
        match self {
            Self::Fixed(ref fixed) => Some(fixed.total_len),
            Self::Partial { .. } => None,
        }
    }
}

impl<R: io::Read> io::Read for LiteralDataGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fixed(ref mut fixed) => fixed.read(buf),
            Self::Partial {
                gen,
                current_packet,
                is_first,
            } => {
                if current_packet.is_none() {
                    match gen.next() {
                        None => {
                            // EOF
                            return Ok(0);
                        }
                        Some(Ok(packet)) => {
                            let mut packet_ser = Vec::new();

                            if *is_first {
                                // only the first packet needs the literal data header
                                packet
                                    .packet_header
                                    .to_writer(&mut packet_ser)
                                    .map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?;

                                packet.header.to_writer(&mut packet_ser).map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, e.to_string())
                                })?;

                                debug!("first partial packet {:?}", packet.packet_header);
                                *is_first = false;
                            } else {
                                // only length
                                packet
                                    .packet_header
                                    .packet_length()
                                    .to_writer_new(&mut packet_ser)
                                    .map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?;
                                debug!("partial packet {:?}", packet.packet_header.packet_length());
                            }

                            packet_ser.extend_from_slice(&packet.data);
                            current_packet.replace(packet_ser.into());
                        }
                        Some(Err(err)) => {
                            return Err(err);
                        }
                    }
                }
                let current_packet_ref = current_packet.as_mut().expect("just checked");

                let to_write = current_packet_ref.remaining().min(buf.len());
                current_packet_ref.copy_to_slice(&mut buf[..to_write]);

                if current_packet_ref.remaining() == 0 {
                    *current_packet = None;
                }

                Ok(to_write)
            }
        }
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
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len as usize);
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
        })
    }

    fn fill_buf(&mut self, chunk_size: usize) -> io::Result<usize> {
        let mut offset = 0;
        loop {
            let read = self.source.read(&mut self.buffer[offset..chunk_size])?;
            offset += read;

            if read == 0 || offset == chunk_size {
                break;
            }
        }

        Ok(offset)
    }
}

impl<R: io::Read> Iterator for LiteralDataPartialGenerator<R> {
    type Item = io::Result<LiteralData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }
        let chunk_size = if self.is_first {
            self.chunk_size as usize - self.header.write_len()
        } else {
            self.chunk_size as usize
        };

        let buf_size = match self.fill_buf(chunk_size) {
            Ok(size) => size,
            Err(err) => {
                self.is_done = true;
                return Some(Err(err));
            }
        };

        debug!("read chunk {} bytes", buf_size);

        debug_assert!(buf_size <= u32::MAX as usize);

        let data = Bytes::from(self.buffer[..buf_size].to_vec());

        let packet_length = if self.is_first && buf_size < chunk_size {
            // all data fits into a single packet
            self.is_first = false;
            self.is_done = true;
            PacketLength::Fixed(buf_size + self.header.write_len())
        } else {
            if self.is_first {
                self.is_first = false;
            }

            if buf_size == chunk_size {
                // partial
                PacketLength::Partial(self.chunk_size)
            } else {
                // final packet, this can be length 0
                self.is_done = true;
                PacketLength::Fixed(data.len())
            }
        };
        let packet_header =
            PacketHeader::from_parts(PacketHeaderVersion::New, Tag::LiteralData, packet_length)
                .expect("known construction");

        Some(Ok(LiteralData {
            packet_header,
            header: self.header.clone(),
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::packet::Packet;

    use super::*;

    #[test]
    fn test_utf8_literal() {
        let slogan = "一门赋予每个人构建可靠且高效软件能力的语言。";
        let literal = LiteralData::from_str("", slogan);
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

        let packet = LiteralData::from_bytes("hello", buf.to_vec().into());

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
    fn test_literal_data_partial_generator() {
        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let chunk_size = 512;
        let file_size = chunk_size * 5 + 100;
        let mut buf = vec![0u8; file_size];
        rng.fill(&mut buf[..]);

        let header = LiteralDataHeader {
            file_name: "hello.txt".into(),
            mode: DataMode::Binary,
            created: Utc::now().trunc_subsecs(0),
        };

        let generator =
            LiteralDataPartialGenerator::new(header, &buf[..], chunk_size as u32).unwrap();

        let packets: Vec<_> = generator.collect();
        assert_eq!(packets.len(), 6, "{:?}", packets);

        for (i, packet) in packets.iter().enumerate().take(5) {
            let packet = packet.as_ref().unwrap();
            assert_eq!(
                packet.packet_header.packet_length(),
                PacketLength::Partial(chunk_size as u32)
            );

            if i == 0 {
                assert_eq!(packet.data.len(), chunk_size - packet.header.write_len());
            } else {
                assert_eq!(packet.data.len(), chunk_size);
            }
        }

        let packet = packets[5].as_ref().unwrap();
        assert_eq!(
            packet.packet_header.packet_length(),
            PacketLength::Fixed(115),
        );
        assert_eq!(packet.data.len(), 115);
    }

    #[test]
    fn test_literal_data_partial_roundtrip() {
        pretty_env_logger::try_init().ok();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let chunk_size = 512;

        let max_file_size = chunk_size * 5 + 100;

        for file_size in 1..=max_file_size {
            println!("size {}", file_size);
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

            let packets: Vec<_> = crate::packet::many::PacketParser::new(out.into()).collect();
            assert_eq!(packets.len(), 1, "{:?}", packets);
            let packet = packets[0].as_ref().unwrap();

            assert_eq!(packet.packet_header().tag(), Tag::LiteralData);
            let Packet::LiteralData(data) = packet else {
                panic!("invalid packet: {:?}", packet);
            };

            assert_eq!(data.header, header);
            assert_eq!(data.data, buf);
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
            let new_packet = LiteralData::from_buf(packet.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
