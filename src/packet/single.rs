use bytes::Buf;
use log::warn;

use crate::errors::{Error, Result};
use crate::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, Packet, PacketHeader,
    Padding, PublicKey, PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey,
    Signature, SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust,
    UserAttribute, UserId,
};
use crate::types::Tag;

impl Packet {
    pub fn from_bytes<B: Buf + std::fmt::Debug>(
        packet_header: PacketHeader,
        mut body: B,
    ) -> Result<Self> {
        let res: Result<Self> = match packet_header.tag() {
            Tag::Signature => Signature::from_buf(packet_header, &mut body).map(Into::into),
            Tag::OnePassSignature => {
                OnePassSignature::from_buf(packet_header, &mut body).map(Into::into)
            }

            Tag::SecretKey => SecretKey::from_buf(packet_header, &mut body).map(Into::into),
            Tag::SecretSubkey => SecretSubkey::from_buf(packet_header, &mut body).map(Into::into),

            Tag::PublicKey => PublicKey::from_buf(packet_header, &mut body).map(Into::into),
            Tag::PublicSubkey => PublicSubkey::from_buf(packet_header, &mut body).map(Into::into),

            Tag::PublicKeyEncryptedSessionKey => {
                PublicKeyEncryptedSessionKey::from_buf(packet_header, &mut body).map(Into::into)
            }
            Tag::SymKeyEncryptedSessionKey => {
                SymKeyEncryptedSessionKey::from_buf(packet_header, &mut body).map(Into::into)
            }

            Tag::LiteralData => LiteralData::from_buf(packet_header, &mut body).map(Into::into),
            Tag::CompressedData => {
                CompressedData::from_buf(packet_header, &mut body).map(Into::into)
            }
            Tag::SymEncryptedData => {
                SymEncryptedData::from_buf(packet_header, &mut body).map(Into::into)
            }
            Tag::SymEncryptedProtectedData => {
                SymEncryptedProtectedData::from_buf(packet_header, &mut body).map(Into::into)
            }

            Tag::Marker => Marker::from_buf(packet_header, &mut body).map(Into::into),
            Tag::Trust => Trust::from_buf(packet_header, &mut body).map(Into::into),
            Tag::UserId => UserId::from_buf(packet_header, &mut body).map(Into::into),
            Tag::UserAttribute => UserAttribute::from_buf(packet_header, &mut body).map(Into::into),
            Tag::ModDetectionCode => {
                ModDetectionCode::from_buf(packet_header, &mut body).map(Into::into)
            }
            Tag::Padding => Padding::from_buf(packet_header, &mut body).map(Into::into),
            Tag::Other(20) => {
                unimplemented_err!("GnuPG-proprietary 'OCB Encrypted Data Packet' is unsupported")
            }
            Tag::Other(22..=39) => {
                // a "hard" error that will bubble up and interrupt processing of compositions
                return Err(Error::InvalidPacketContent(Box::new(Error::Message(
                    format!("Unassigned Critical Packet type {:?}", packet_header.tag()),
                ))));
            }
            Tag::Other(40..=59) => {
                // a "soft" error that will usually get ignored while processing packet streams
                unsupported_err!(
                    "Unsupported but non-critical packet type: {:?}",
                    packet_header.tag()
                )
            }
            Tag::Other(other) => unimplemented_err!("Unknown packet type: {}", other),
        };

        match res {
            Ok(res) => Ok(res),
            Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
            Err(err) => {
                warn!(
                    "invalid packet: {:#?} {:?}\n{:?}",
                    err,
                    packet_header.tag(),
                    body
                );
                Err(Error::InvalidPacketContent(Box::new(err)))
            }
        }
    }
}
