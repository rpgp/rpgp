use bytes::{Buf, Bytes};
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
    // TODO: switch to Buf once fully converted
    pub fn from_bytes(packet_header: PacketHeader, mut body: Bytes) -> Result<Self> {
        if let Some(len) = packet_header.packet_length().maybe_len() {
            ensure_eq!(len, body.len(), "inconsistent packet length");
        }

        let res: Result<Self> = match packet_header.tag() {
            Tag::Signature => Signature::from_buf(packet_header, &mut body).map(Into::into),
            Tag::OnePassSignature => {
                OnePassSignature::from_buf(packet_header, &mut body).map(Into::into)
            }

            Tag::SecretKey => SecretKey::from_slice(packet_header, &body).map(Into::into),
            Tag::SecretSubkey => SecretSubkey::from_slice(packet_header, &body).map(Into::into),

            Tag::PublicKey => PublicKey::from_slice(packet_header, &body).map(Into::into),
            Tag::PublicSubkey => PublicSubkey::from_slice(packet_header, &body).map(Into::into),

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
                    hex::encode(body)
                );
                Err(Error::InvalidPacketContent(Box::new(err)))
            }
        }
    }

    /// Parses the body for partial packets
    pub fn from_buf_partial<B: Buf + std::fmt::Debug>(
        ver: PacketHeader,
        mut body: B,
    ) -> Result<Self> {
        let res: Result<Self> = match ver.tag() {
            Tag::CompressedData => CompressedData::from_buf(ver, &mut body).map(Into::into),
            Tag::SymEncryptedData => SymEncryptedData::from_buf(ver, &mut body).map(Into::into),
            Tag::LiteralData => LiteralData::from_buf(ver, &mut body).map(Into::into),
            Tag::SymEncryptedProtectedData => {
                SymEncryptedProtectedData::from_buf(ver, &mut body).map(Into::into)
            }
            _ => {
                // a "hard" error that will bubble up and interrupt processing of compositions
                return Err(Error::InvalidPacketContent(Box::new(Error::Message(
                    format!("invalid packet type with partical length {:?}", ver.tag()),
                ))));
            }
        };

        match res {
            Ok(res) => Ok(res),
            Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
            Err(err) => {
                warn!("invalid packet: {:?} {:?}\n{:?}", err, ver.tag(), body);
                Err(Error::InvalidPacketContent(Box::new(err)))
            }
        }
    }
}
