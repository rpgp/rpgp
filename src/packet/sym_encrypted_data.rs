use std::io;

use bytes::{Buf, Bytes};

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;

use super::PacketHeader;

/// Symmetrically Encrypted Data Packet
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
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        Ok(SymEncryptedData {
            packet_header,
            data: input.copy_to_bytes(input.remaining()),
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
