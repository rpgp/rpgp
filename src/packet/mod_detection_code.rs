use std::io;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Modification Detection Code Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#version-one-seipd>
///
/// Also see <https://www.rfc-editor.org/rfc/rfc9580.html#name-terminology-changes>:
///
/// "Modification Detection Code" or "MDC" was originally described as a distinct packet
/// (Packet Type ID 19), and its corresponding flag in the Features signature subpacket
/// (Section 5.2.3.32) was known as "Modification Detection".
/// It is now described as an intrinsic part of v1 SEIPD (Section 5.13.1), and the same
/// corresponding flag is known as "Version 1 Symmetrically Encrypted and Integrity Protected
/// Data packet".
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct ModDetectionCode {
    packet_version: Version,
    /// 20 byte SHA1 hash of the preceding plaintext data.
    #[debug("{}", hex::encode(hash))]
    hash: [u8; 20],
}

impl ModDetectionCode {
    /// Parses a `ModDetectionCode` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure_eq!(input.len(), 20, "invalid input len");

        let mut hash = [0u8; 20];
        hash.copy_from_slice(input);

        Ok(ModDetectionCode {
            packet_version,
            hash,
        })
    }
}

impl Serialize for ModDetectionCode {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.hash[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.hash.len()
    }
}

impl PacketTrait for ModDetectionCode {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::ModDetectionCode
    }
}
