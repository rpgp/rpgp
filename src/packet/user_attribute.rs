use std::{fmt, io};

use chrono::{SubsecRound, Utc};

use byteorder::{LittleEndian, WriteBytesExt};
use nom::{be_u8, le_u16, rest};

use errors::Result;
use packet::{PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket};
use ser::Serialize;
use types::{SecretKeyTrait, SignedUserAttribute, Tag, Version};
use util::{packet_length, write_packet_length};

/// User Attribute Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq)]
pub enum UserAttribute {
    Image {
        packet_version: Version,
        header: Vec<u8>,
        data: Vec<u8>,
    },
    Unknown {
        packet_version: Version,
        typ: u8,
        data: Vec<u8>,
    },
}

impl UserAttribute {
    /// Parses a `UserAttribute` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttribute::Image { .. } => 1,
            UserAttribute::Unknown { typ, .. } => typ,
        }
    }

    pub fn packet_len(&self) -> usize {
        match self {
            UserAttribute::Image { ref data, .. } => {
                // typ + image header + data length
                1 + 16 + data.len()
            }
            UserAttribute::Unknown { ref data, .. } => {
                // typ + data length
                1 + data.len()
            }
        }
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUserAttribute>
    where
        F: FnOnce() -> String,
    {
        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::CertGeneric)
            .pub_alg(key.algorithm())
            .hashed_subpackets(vec![Subpacket::SignatureCreationTime(
                Utc::now().trunc_subsecs(0),
            )])
            .unhashed_subpackets(vec![Subpacket::Issuer(
                key.key_id().expect("missing key id"),
            )])
            .build()?;

        let sig = config.sign_certificate(key, key_pw, self.tag(), &self)?;

        Ok(SignedUserAttribute::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUserAttribute {
        SignedUserAttribute::new(self, vec![sig])
    }
}

impl fmt::Display for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserAttribute::Image { data, .. } => {
                write!(f, "User Attribute: Image (len: {})", data.len())
            }
            UserAttribute::Unknown { typ, data, .. } => {
                write!(f, "User Attribute: typ: {} (len: {})", typ, data.len())
            }
        }
    }
}

#[rustfmt::skip]
named_args!(image(packet_version: Version) <UserAttribute>, do_parse!(
    // little endian, for historical reasons..
       header_len: le_u16
    >>     header: take!(header_len - 2)
    // the actual image is the rest
    >>         img: rest
    >> (UserAttribute::Image {
        packet_version,
        header: header.to_vec(),
        data: img.to_vec()
    })
));

#[rustfmt::skip]
named_args!(parse(packet_version: Version) <UserAttribute>, do_parse!(
        len: packet_length
    >>  typ: be_u8
    >> attr: flat_map!(
        take!(len-1),
        switch!(value!(typ),
                1 => call!(image, packet_version) |
                _ => map!(rest, |data| UserAttribute::Unknown {
                    packet_version,
                    typ,
                    data: data.to_vec()
                })
        ))
    >> ({
        info!("attr with len {}", len);
        attr
    })
));

impl Serialize for UserAttribute {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        info!("write_packet_len {}", self.packet_len());
        write_packet_length(self.packet_len(), writer)?;

        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ..
            } => {
                // typ: image
                writer.write_all(&[0x01])?;
                writer.write_u16::<LittleEndian>((header.len() + 2) as u16)?;
                writer.write_all(header)?;

                // actual data
                writer.write_all(data)?;
            }
            UserAttribute::Unknown { ref data, typ, .. } => {
                writer.write_all(&[*typ])?;
                writer.write_all(data)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserAttribute::Image {
                ref header,
                ref data,
                ..
            } => f
                .debug_struct("UserAttribute::Image")
                .field("header", &hex::encode(header))
                .field("data", &hex::encode(data))
                .finish(),
            UserAttribute::Unknown { typ, ref data, .. } => f
                .debug_struct("UserAttribute::Image")
                .field("type", &hex::encode(&[*typ]))
                .field("data", &hex::encode(data))
                .finish(),
        }
    }
}

impl PacketTrait for UserAttribute {
    fn packet_version(&self) -> Version {
        match self {
            UserAttribute::Image { packet_version, .. } => *packet_version,
            UserAttribute::Unknown { packet_version, .. } => *packet_version,
        }
    }

    fn tag(&self) -> Tag {
        Tag::UserAttribute
    }
}
