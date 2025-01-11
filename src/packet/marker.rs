use std::io;

use bytes::Buf;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// PGP as UTF-8 octets.
const PGP: [u8; 3] = [0x50, 0x47, 0x50];

/// Marker Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-marker-packet-type-id-10>
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Marker {
    packet_version: Version,
}

impl Marker {
    /// Parses a `Marker` packet from the given slice.
    pub fn from_buf<B: Buf>(packet_version: Version, mut input: B) -> Result<Self> {
        let marker = input.read_array::<3>()?;
        ensure_eq!(marker, PGP, "invalid input");

        Ok(Marker { packet_version })
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

impl Serialize for Marker {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&PGP[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        PGP.len()
    }
}

impl PacketTrait for Marker {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Marker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn write_len(marker: Marker) {
            let mut buf = Vec::new();
            marker.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), marker.write_len());
        }


        #[test]
        fn packet_roundtrip(marker: Marker) {
            let mut buf = Vec::new();
            marker.to_writer(&mut buf).unwrap();
            let new_marker = Marker::from_buf(marker.packet_version, &mut &buf[..]).unwrap();
            assert_eq!(marker, new_marker);
        }
    }
}
