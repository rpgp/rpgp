use std::io::{BufRead, Write};

use bytes::Bytes;

use crate::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        sym::SymmetricKeyAlgorithm,
    },
    errors::{ensure_eq, InvalidInputSnafu, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Tag,
};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Config {
    pub sym_alg: SymmetricKeyAlgorithm,
    pub aead: AeadAlgorithm,
    pub chunk_size: ChunkSize,
    pub iv: Vec<u8>,
}

impl Config {
    pub fn try_from_reader<R: BufRead>(mut data: R) -> Result<Self> {
        // A one-octet version number. The only currently defined value is 1.
        let version = data.read_u8()?;
        ensure_eq!(
            version,
            0x01,
            "GnupgAead version {} is unsupported",
            version
        );

        // A one-octet cipher algorithm.
        let sym_alg = data.read_u8().map(SymmetricKeyAlgorithm::from)?;

        // A one-octet encryption mode octet with the fixed value 0x02.
        // If decryption using the EAX mode is supported this octet may have the value 0x01.
        let aead = data.read_u8().map(AeadAlgorithm::from)?;
        ensure_eq!(
            aead,
            AeadAlgorithm::Ocb,
            "GnupgAead AEAD mode {:?} is unsupported",
            aead
        );

        // A one-octet chunk size.
        // (Note: GnupgAead chunk size is encoded in the same way as for SEIPDv2)
        let chunk_size = data
            .read_u8()?
            .try_into()
            .map_err(|_| InvalidInputSnafu.build())?;

        // A starting initialization vector of size specified by the encryption mode (15 octets for OCB).
        let iv = data.read_array::<15>()?; // OCB iv size

        Ok(Self {
            sym_alg,
            aead,
            chunk_size,
            iv: iv.into(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct GnupgAeadData {
    packet_header: PacketHeader,
    config: Config,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl GnupgAeadData {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::GnupgAead, "invalid tag");

        let config = Config::try_from_reader(&mut data)?;
        let data = data.rest()?;

        Ok(Self {
            packet_header,
            config,
            data: data.freeze(),
        })
    }
}

impl Serialize for GnupgAeadData {
    fn to_writer<W: Write>(&self, _: &mut W) -> Result<()> {
        todo!()
    }

    fn write_len(&self) -> usize {
        todo!()
    }
}

impl PacketTrait for GnupgAeadData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
