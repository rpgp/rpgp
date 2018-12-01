use std::{fmt, io, str};

use errors::Result;
use ser::Serialize;
use types::Version;
use util::read_string_lossy;

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserId {
    packet_version: Version,
    id: String,
}

impl UserId {
    /// Parses a `UserId` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let id = read_string_lossy(input);

        Ok(UserId { packet_version, id })
    }

    pub fn from_str(packet_version: Version, input: &str) -> Self {
        UserId {
            packet_version,
            id: input.to_string(),
        }
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl Serialize for UserId {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.id.as_bytes())?;

        Ok(())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "User ID: \"{}\"", self.id)
    }
}
