use std::io::{self, BufRead};

use bytes::Bytes;

use super::PacketHeader;
use crate::{errors::Result, packet::PacketTrait, parsing_reader::BufReadParsing, ser::Serialize};

/// Symmetrically Encrypted Data Packet
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetrically-encrypted-dat>
///
/// "This packet is obsolete. An implementation MUST NOT create this packet.
/// An implementation SHOULD reject such a packet and stop processing the message.
/// If an implementation chooses to process the packet anyway, it MUST return a clear warning
/// that a non-integrity-protected packet has been processed."
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct SymEncryptedData {
    packet_header: PacketHeader,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl SymEncryptedData {
    /// Parses a `SymEncryptedData` packet from the given buffer.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let data = input.rest()?;
        Ok(SymEncryptedData {
            packet_header,
            data: data.freeze(),
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for SymEncryptedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.data.len()
    }
}

impl PacketTrait for SymEncryptedData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

#[cfg(test)]
mod tests {
    use prop::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::types::{PacketHeaderVersion, PacketLength, Tag};

    impl Arbitrary for SymEncryptedData {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<PacketHeaderVersion>()
                .prop_flat_map(move |packet_header_version| {
                    (Just(packet_header_version), vec(0u8..=255u8, 0..=2048))
                })
                .prop_map(move |(packet_header_version, data)| {
                    let len = 1u32; // unused

                    let packet_header = PacketHeader::from_parts(
                        packet_header_version,
                        Tag::SymEncryptedData,
                        PacketLength::Fixed(len),
                    )
                    .unwrap();

                    SymEncryptedData {
                        packet_header,
                        data: data.into(),
                    }
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn write_len(data: SymEncryptedData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), data.write_len());
        }


        #[test]
        fn packet_roundtrip(data: SymEncryptedData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            let new_data = SymEncryptedData::try_from_reader(data.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(data, new_data);
        }
    }
}
