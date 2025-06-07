use std::io::{BufRead, Write};

use bytes::Bytes;

use crate::{
    errors::{ensure_eq, Result},
    packet::{
        sym_encrypted_protected_data::Config, PacketHeader, PacketTrait,
        SymEncryptedProtectedDataConfig,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Tag,
};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct LibreOcbData {
    packet_header: PacketHeader,
    config: Config,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl LibreOcbData {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::LibreOcb, "invalid tag");

        let config = SymEncryptedProtectedDataConfig::try_from_reader_libre_ocb(&mut data)?;
        let data = data.rest()?;

        Ok(Self {
            packet_header,
            config,
            data: data.freeze(),
        })
    }
}

impl Serialize for LibreOcbData {
    fn to_writer<W: Write>(&self, _: &mut W) -> Result<()> {
        todo!()
    }

    fn write_len(&self) -> usize {
        todo!()
    }
}

impl PacketTrait for LibreOcbData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
