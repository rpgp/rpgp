use std::{fmt, io, str};

use chrono::Utc;

use errors::Result;
use packet::{PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket};
use ser::Serialize;
use types::{SecretKeyTrait, SignedUser, Tag, Version};
use util::{read_string, write_string};

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    packet_version: Version,
    id: String,
}

impl UserId {
    /// Parses a `UserId` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let id = read_string(input);

        Ok(UserId { packet_version, id })
    }

    pub fn from_str(packet_version: Version, input: &str) -> Self {
        UserId {
            packet_version,
            id: input.to_string(),
        }
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUser>
    where
        F: FnOnce() -> String,
    {
        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::CertGeneric)
            .pub_alg(key.algorithm())
            .hashed_subpackets(vec![Subpacket::SignatureCreationTime(Utc::now())])
            .unhashed_subpackets(vec![Subpacket::Issuer(
                key.key_id().expect("missing key id"),
            )])
            .build()?;

        let sig = config.sign_certificate(key, key_pw, self.tag(), &self)?;

        Ok(SignedUser::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUser {
        SignedUser::new(self, vec![sig])
    }
}

impl Serialize for UserId {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&write_string(&self.id))?;

        Ok(())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "User ID: \"{}\"", self.id)
    }
}

impl PacketTrait for UserId {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::UserId
    }
}
