use std::io::BufRead;

use log::warn;

use crate::{
    errors::{format_err, Error, Result, UnsupportedSnafu},
    packet::{
        CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, Packet,
        PacketHeader, Padding, PublicKey, PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey,
        SecretSubkey, Signature, SymEncryptedData, SymEncryptedProtectedData,
        SymKeyEncryptedSessionKey, Trust, UserAttribute, UserId,
    },
    parsing_reader::BufReadParsing,
    types::Tag,
};

impl Packet {
    pub fn from_reader<R: BufRead>(packet_header: PacketHeader, mut body: R) -> Result<Self> {
        let res: Result<Self> = match packet_header.tag() {
            Tag::Signature => Signature::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::OnePassSignature => {
                OnePassSignature::try_from_reader(packet_header, &mut body).map(Into::into)
            }

            Tag::SecretKey => SecretKey::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::SecretSubkey => {
                SecretSubkey::try_from_reader(packet_header, &mut body).map(Into::into)
            }

            Tag::PublicKey => PublicKey::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::PublicSubkey => {
                PublicSubkey::try_from_reader(packet_header, &mut body).map(Into::into)
            }

            Tag::PublicKeyEncryptedSessionKey => {
                PublicKeyEncryptedSessionKey::try_from_reader(packet_header, &mut body)
                    .map(Into::into)
            }
            Tag::SymKeyEncryptedSessionKey => {
                SymKeyEncryptedSessionKey::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::LiteralData => {
                LiteralData::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::CompressedData => {
                CompressedData::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::SymEncryptedData => {
                SymEncryptedData::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::SymEncryptedProtectedData => {
                SymEncryptedProtectedData::try_from_reader(packet_header, &mut body).map(Into::into)
            }

            Tag::Marker => Marker::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::Trust => Trust::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::UserId => UserId::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::UserAttribute => {
                UserAttribute::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::ModDetectionCode => {
                ModDetectionCode::try_from_reader(packet_header, &mut body).map(Into::into)
            }
            Tag::Padding => Padding::try_from_reader(packet_header, &mut body).map(Into::into),
            Tag::Other(20) => Err(UnsupportedSnafu {
                message: "GnuPG-proprietary 'OCB Encrypted Data Packet' is unsupported".to_string(),
            }
            .build()),
            Tag::Other(22..=39) => {
                // a "hard" error that will bubble up and interrupt processing of compositions
                Err(Error::InvalidPacketContent {
                    source: Box::new(format_err!(
                        "Unassigned Critical Packet type {:?}",
                        packet_header.tag()
                    )),
                })
            }
            Tag::Other(40..=59) => {
                // a "soft" error that will usually get ignored while processing packet streams
                Err(UnsupportedSnafu {
                    message: format!("Unassigned Critical Packet type {:?}", packet_header.tag()),
                }
                .build())
            }
            Tag::Other(other) => Err(UnsupportedSnafu {
                message: format!("Unknown packet type: {}", other),
            }
            .build()),
        };

        if let Err(ref err) = res {
            log::info!("error {:#?}", err);
        }

        // always drain the body to makes sure all data has been consumed
        let drained_bytes = body.drain()?;
        match res {
            Ok(res) => {
                if drained_bytes > 0 {
                    warn!("failed to consume data: {} bytes too many", drained_bytes);
                    return Err(Error::PacketTooLarge {
                        size: drained_bytes,
                    });
                }
                Ok(res)
            }
            Err(Error::PacketParsing { source }) if source.is_incomplete() => {
                Err(Error::PacketIncomplete { source })
            }
            Err(Error::IO { source, backtrace })
                if source.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                Err(Error::PacketIncomplete {
                    source: Box::new(crate::parsing::Error::UnexpectedEof { source, backtrace }),
                })
            }
            Err(err) => {
                warn!("invalid packet: {:#?} {:?}", err, packet_header.tag());
                Err(Error::InvalidPacketContent {
                    source: Box::new(err),
                })
            }
        }
    }
}
