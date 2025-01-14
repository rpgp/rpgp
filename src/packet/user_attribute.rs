use std::io;

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use chrono::{SubsecRound, Utc};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};

use crate::errors::Result;
use crate::packet::{
    PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{KeyVersion, PublicKeyTrait, SecretKeyTrait, SignedUserAttribute};
use crate::util::{packet_length_buf, write_packet_length, write_packet_length_len};

#[cfg(test)]
use proptest::prelude::*;

/// The type of a user attribute. Only `Image` is a known type currently
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive, derive_more::Display)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
pub enum UserAttributeType {
    #[display("Image")]
    Image = 0x01,
    #[num_enum(catch_all)]
    #[display("Unknown({:x})", 0)]
    Unknown(#[cfg_attr(test, proptest(filter = "|i| *i != 1"))] u8),
}

/// User Attribute Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-user-attribute-packet-type->
#[derive(Clone, PartialEq, Eq, derive_more::Debug, derive_more::Display)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum UserAttribute {
    #[display("User Attribute: Image (len: {})", data.len())]
    Image {
        packet_header: PacketHeader,
        #[debug("{}", hex::encode(header))]
        #[cfg_attr(
            test,
            proptest(
                strategy = "any::<Vec<u8>>().prop_map(Into::into)",
                filter = "|d| !d.is_empty()"
            )
        )]
        header: Bytes,
        #[debug("{}", hex::encode(data))]
        #[cfg_attr(
            test,
            proptest(
                strategy = "any::<Vec<u8>>().prop_map(Into::into)",
                filter = "|d| !d.is_empty()"
            )
        )]
        data: Bytes,
    },
    #[display("User Attribute: {} (len: {})", typ, data.len())]
    Unknown {
        packet_header: PacketHeader,
        #[cfg_attr(test, proptest(filter = "|t| *t != UserAttributeType::Image"))]
        typ: UserAttributeType,
        #[debug("{}", hex::encode(data))]
        #[cfg_attr(
            test,
            proptest(
                strategy = "any::<Vec<u8>>().prop_map(Into::into)",
                filter = "|d| !d.is_empty()"
            )
        )]
        data: Bytes,
    },
}

impl UserAttribute {
    /// Parses a `UserAttribute` packet from the given buffer.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        let len = packet_length_buf(&mut i)?;
        if len < 1 {
            return Err(crate::errors::Error::InvalidInput);
        }

        let typ = i.read_u8().map(UserAttributeType::from)?;

        let mut body = i.read_take(len - 1)?;
        match typ {
            UserAttributeType::Image => {
                // little endian, for historical reasons..
                let len = body.read_le_u16()? as usize;
                if len < 2 {
                    return Err(crate::errors::Error::InvalidInput);
                }

                let header = body.copy_to_bytes(len - 2);
                let data = body.rest();

                // the actual image is the rest
                Ok(UserAttribute::Image {
                    packet_header,
                    header,
                    data,
                })
            }
            UserAttributeType::Unknown(_) => Ok(UserAttribute::Unknown {
                packet_header,
                typ,
                data: body.rest(),
            }),
        }
    }

    /// Returns typ of this user attribute.
    pub fn typ(&self) -> UserAttributeType {
        match self {
            UserAttribute::Image { .. } => UserAttributeType::Image,
            UserAttribute::Unknown { typ, .. } => *typ,
        }
    }

    /// Create a self-signature
    pub fn sign<R, F>(
        &self,
        rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        self.sign_third_party(rng, key, key_pw, key)
    }

    /// Create a third-party signature
    pub fn sign_third_party<R, F>(
        &self,
        mut rng: R,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        let hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            Utc::now().trunc_subsecs(0),
        ))];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))];

        let mut config = match signer.version() {
            KeyVersion::V4 => SignatureConfig::v4(
                SignatureType::CertGeneric,
                signer.algorithm(),
                signer.hash_alg(),
            ),

            KeyVersion::V6 => SignatureConfig::v6(
                &mut rng,
                SignatureType::CertGeneric,
                signer.algorithm(),
                signer.hash_alg(),
            )?,
            v => unsupported_err!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = hashed_subpackets;
        config.unhashed_subpackets = unhashed_subpackets;

        let sig =
            config.sign_certification_third_party(signer, signer_pw, signee, self.tag(), &self)?;

        Ok(SignedUserAttribute::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUserAttribute {
        SignedUserAttribute::new(self, vec![sig])
    }

    fn packet_len(&self) -> usize {
        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ..
            } => {
                // typ + image header + header length + data length
                1 + header.len() + 2 + data.len()
            }
            UserAttribute::Unknown { ref data, .. } => {
                // typ + data length
                1 + data.len()
            }
        }
    }
}

impl Serialize for UserAttribute {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet_length(self.packet_len(), writer)?;

        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ..
            } => {
                // typ: image
                writer.write_u8(0x01)?;
                writer.write_u16::<LittleEndian>((header.len() + 2).try_into()?)?;
                writer.write_all(header)?;

                // actual data
                writer.write_all(data)?;
            }
            UserAttribute::Unknown { ref data, typ, .. } => {
                writer.write_u8((*typ).into())?;
                writer.write_all(data)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let packet_len = self.packet_len();
        let mut sum = write_packet_length_len(packet_len);
        sum += packet_len;
        sum
    }
}

impl PacketTrait for UserAttribute {
    fn packet_header(&self) -> &PacketHeader {
        match self {
            UserAttribute::Image { packet_header, .. } => packet_header,
            UserAttribute::Unknown { packet_header, .. } => packet_header,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn write_len(attr: UserAttribute) {
            let mut buf = Vec::new();
            attr.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), attr.write_len());
        }


        #[test]
        fn packet_roundtrip(attr: UserAttribute) {
            let mut buf = Vec::new();
            attr.to_writer(&mut buf).unwrap();
            let new_attr = UserAttribute::from_buf(*attr.packet_header(), &mut &buf[..]).unwrap();
            assert_eq!(attr, new_attr);
        }
    }
}
