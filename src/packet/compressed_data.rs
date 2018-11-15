use std::io::Cursor;

use flate2::read::{DeflateDecoder, ZlibDecoder};

use packet::packet_trait::Packet;
use packet::types::{CompressionAlgorithm, Tag};

#[derive(Debug, Clone)]
pub struct CompressedData {
    compression_algorithm: CompressionAlgorithm,
    compressed_data: Vec<u8>,
}

impl Packet for CompressedData {
    fn tag(&self) -> Tag {
        Tag::CompressedData
    }
}

pub enum Decompressor<R> {
    Uncompressed(Cursor<R>),
    Zip(DeflateDecoder<R>),
    Zlib(ZlibDecoder<R>),
    Bzip2,
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "input too short");

        let alg = CompressionAlgorithm::from_u8(input[0])?;
        Ok(CompressedData {
            compression_algorithm: alg,
            compressed_data: &input[1..].to_vec(),
        })
    }

    pub fn decompress<'a>(&'a self) -> Decompressor<&'a [u8]> {
        match self.compression_algorithm {
            CompressionAlgorithm::Uncompressed => {
                Decompressor::Uncompressed(Cursor::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::ZIP => {
                Decompressor::Zip(DeflateDecoder::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::ZLIB => {
                Decompressor::Zlib(ZlibDecoder::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::BZip2 => unimplemented!("BZip2"),
        }
    }
}
