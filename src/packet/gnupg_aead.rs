use std::io::{BufRead, Write};

use byteorder::WriteBytesExt;
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

const GNUPG_AEAD_VERSION_1: u8 = 0x01;

/// Config for a [GnupgAeadData] encryption container.
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Config {
    pub sym_alg: SymmetricKeyAlgorithm,
    pub aead: AeadAlgorithm,
    pub chunk_size: ChunkSize,
    #[debug("{}", hex::encode(iv))]
    pub iv: Bytes,
}

impl Config {
    pub fn try_from_reader<R: BufRead>(mut data: R) -> Result<Self> {
        // A one-octet version number. The only currently defined value is 1.
        let version = data.read_u8()?;
        ensure_eq!(
            version,
            GNUPG_AEAD_VERSION_1,
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

        // A starting initialization vector of size specified by the encryption mode.
        let iv = data.take_bytes(aead.iv_size())?.into();

        Ok(Self {
            sym_alg,
            aead,
            chunk_size,
            iv,
        })
    }
}

impl Serialize for Config {
    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(GNUPG_AEAD_VERSION_1)?;
        writer.write_u8(self.sym_alg.into())?;
        writer.write_u8(self.aead.into())?;
        writer.write_u8(self.chunk_size.into())?;
        writer.write_all(&self.iv)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        4 + self.iv.len()
    }
}

/// GnuPG's proprietary AEAD format "OCB Encrypted Data Packet" (packet type 20).
/// <https://www.ietf.org/archive/id/draft-koch-librepgp-03.html#name-ocb-encrypted-data-packet-t>
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
    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.config.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for GnupgAeadData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

#[cfg(test)]
mod tests {
    use prop::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::types::{PacketHeaderVersion, PacketLength};

    impl Arbitrary for Config {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<(SymmetricKeyAlgorithm, ChunkSize)>()
                .prop_flat_map(move |(sym_alg, chunk_size)| {
                    (Just(sym_alg), Just(chunk_size), vec(0u8..=255u8, 15))
                })
                .prop_map(move |(sym_alg, chunk_size, iv)| Config {
                    sym_alg,
                    aead: AeadAlgorithm::Ocb,
                    chunk_size,
                    iv: iv.into(),
                })
                .boxed()
        }
    }

    impl Arbitrary for GnupgAeadData {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<Config>()
                .prop_flat_map(move |config| (Just(config), vec(0u8..=255u8, 0..=2048)))
                .prop_map(move |(config, data)| {
                    let len = 1u32; // unused
                    let packet_header = PacketHeader::from_parts(
                        PacketHeaderVersion::New,
                        Tag::GnupgAead,
                        PacketLength::Fixed(len),
                    )
                    .unwrap();
                    GnupgAeadData {
                        config,
                        packet_header,
                        data: data.into(),
                    }
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn write_len(data: GnupgAeadData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), data.write_len());
        }


        #[test]
        fn packet_roundtrip(data: GnupgAeadData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            let new_data = GnupgAeadData::try_from_reader(data.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(data, new_data);
        }
    }
}
