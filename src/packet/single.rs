use bytes::{Buf, Bytes};
use log::warn;

use crate::errors::{Error, Result};
use crate::packet::packet_sum::Packet;
use crate::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, Padding, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use crate::types::{Tag, Version};

// TODO: switch to Buf once fully converted
pub fn body_parser_bytes(ver: Version, tag: Tag, mut body: Bytes) -> Result<Packet> {
    let res: Result<Packet> = match tag {
        Tag::Signature => Signature::from_buf(ver, &mut body).map(Into::into),
        Tag::OnePassSignature => OnePassSignature::from_buf(ver, &mut body).map(Into::into),

        Tag::SecretKey => SecretKey::from_slice(ver, &body).map(Into::into),
        Tag::SecretSubkey => SecretSubkey::from_slice(ver, &body).map(Into::into),

        Tag::PublicKey => PublicKey::from_slice(ver, &body).map(Into::into),
        Tag::PublicSubkey => PublicSubkey::from_slice(ver, &body).map(Into::into),

        Tag::PublicKeyEncryptedSessionKey => {
            PublicKeyEncryptedSessionKey::from_buf(ver, &mut body).map(Into::into)
        }
        Tag::SymKeyEncryptedSessionKey => {
            SymKeyEncryptedSessionKey::from_buf(ver, &mut body).map(Into::into)
        }

        Tag::LiteralData => LiteralData::from_buf(ver, &mut body).map(Into::into),
        Tag::CompressedData => CompressedData::from_buf(ver, &mut body).map(Into::into),
        Tag::SymEncryptedData => SymEncryptedData::from_buf(ver, &mut body).map(Into::into),
        Tag::SymEncryptedProtectedData => {
            SymEncryptedProtectedData::from_buf(ver, &mut body).map(Into::into)
        }

        Tag::Marker => Marker::from_buf(ver, &mut body).map(Into::into),
        Tag::Trust => Trust::from_buf(ver, &mut body).map(Into::into),
        Tag::UserId => UserId::from_buf(ver, &mut body).map(Into::into),
        Tag::UserAttribute => UserAttribute::from_buf(ver, &mut body).map(Into::into),
        Tag::ModDetectionCode => ModDetectionCode::from_buf(ver, &mut body).map(Into::into),
        Tag::Padding => Padding::from_buf(ver, &mut body).map(Into::into),
        Tag::Other(20) => {
            unimplemented_err!("GnuPG-proprietary 'OCB Encrypted Data Packet' is unsupported")
        }
        Tag::Other(22..=39) => {
            // a "hard" error that will bubble up and interrupt processing of compositions
            return Err(Error::InvalidPacketContent(Box::new(Error::Message(
                format!("Unassigned Critical Packet type {:?}", tag),
            ))));
        }
        Tag::Other(40..=59) => {
            // a "soft" error that will usually get ignored while processing packet streams
            unsupported_err!("Unsupported but non-critical packet type: {:?}", tag)
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
                tag,
                hex::encode(body)
            );
            Err(Error::InvalidPacketContent(Box::new(err)))
        }
    }
}

/// Parses the body for partial packets
pub fn body_parser_buf<B: Buf + std::fmt::Debug>(
    ver: Version,
    tag: Tag,
    mut body: B,
) -> Result<Packet> {
    let res: Result<Packet> = match tag {
        Tag::CompressedData => CompressedData::from_buf(ver, &mut body).map(Into::into),
        Tag::SymEncryptedData => SymEncryptedData::from_buf(ver, &mut body).map(Into::into),
        Tag::LiteralData => LiteralData::from_buf(ver, &mut body).map(Into::into),
        Tag::SymEncryptedProtectedData => {
            SymEncryptedProtectedData::from_buf(ver, &mut body).map(Into::into)
        }
        _ => {
            // a "hard" error that will bubble up and interrupt processing of compositions
            return Err(Error::InvalidPacketContent(Box::new(Error::Message(
                format!("invalid packet type with partical length {:?}", tag),
            ))));
        }
    };

    match res {
        Ok(res) => Ok(res),
        Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
        Err(err) => {
            warn!("invalid packet: {:?} {:?}\n{:?}", err, tag, body);
            Err(Error::InvalidPacketContent(Box::new(err)))
        }
    }
}
