use std::io;

use log::warn;

use crate::{
    errors::Result,
    packet::{
        CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PacketHeader,
        Padding, PublicKey, PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey,
        Signature, SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust,
        UserAttribute, UserId,
    },
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag},
};

/// Represents a Packet. A packet is the record structure used to encode a chunk of data in OpenPGP.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-syntax>
#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: fix me
pub enum Packet {
    CompressedData(CompressedData),
    PublicKey(PublicKey),
    PublicSubkey(PublicSubkey),
    SecretKey(SecretKey),
    SecretSubkey(SecretSubkey),
    LiteralData(LiteralData),
    Marker(Marker),
    ModDetectionCode(ModDetectionCode),
    OnePassSignature(OnePassSignature),
    PublicKeyEncryptedSessionKey(PublicKeyEncryptedSessionKey),
    Signature(Signature),
    SymEncryptedData(SymEncryptedData),
    SymEncryptedProtectedData(SymEncryptedProtectedData),
    SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey),
    Trust(Trust),
    UserAttribute(UserAttribute),
    UserId(UserId),
    Padding(Padding),
}

impl_try_from_into!(
    Packet,
    CompressedData => CompressedData,
    PublicKey => PublicKey,
    PublicSubkey => PublicSubkey,
    SecretKey => SecretKey,
    SecretSubkey => SecretSubkey,
    LiteralData => LiteralData,
    Marker => Marker,
    ModDetectionCode => ModDetectionCode,
    OnePassSignature => OnePassSignature,
    PublicKeyEncryptedSessionKey => PublicKeyEncryptedSessionKey,
    Signature => Signature,
    SymEncryptedData => SymEncryptedData,
    SymEncryptedProtectedData => SymEncryptedProtectedData,
    SymKeyEncryptedSessionKey => SymKeyEncryptedSessionKey,
    Trust => Trust,
    UserAttribute => UserAttribute,
    UserId => UserId,
    Padding => Padding
);

impl Serialize for Packet {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::CompressedData(p) => p.to_writer_with_header(writer),
            Self::PublicKey(p) => p.to_writer_with_header(writer),
            Self::PublicSubkey(p) => p.to_writer_with_header(writer),
            Self::SecretKey(p) => p.to_writer_with_header(writer),
            Self::SecretSubkey(p) => p.to_writer_with_header(writer),
            Self::LiteralData(p) => p.to_writer_with_header(writer),
            Self::Marker(p) => p.to_writer_with_header(writer),
            Self::ModDetectionCode(p) => p.to_writer_with_header(writer),
            Self::OnePassSignature(p) => p.to_writer_with_header(writer),
            Self::PublicKeyEncryptedSessionKey(p) => p.to_writer_with_header(writer),
            Self::Signature(p) => p.to_writer_with_header(writer),
            Self::SymEncryptedData(p) => p.to_writer_with_header(writer),
            Self::SymEncryptedProtectedData(p) => p.to_writer_with_header(writer),
            Self::SymKeyEncryptedSessionKey(p) => p.to_writer_with_header(writer),
            Self::Trust(p) => p.to_writer_with_header(writer),
            Self::UserAttribute(p) => p.to_writer_with_header(writer),
            Self::UserId(p) => p.to_writer_with_header(writer),
            Self::Padding(p) => p.to_writer_with_header(writer),
        }
    }

    fn write_len(&self) -> usize {
        match self {
            Self::CompressedData(p) => p.write_len_with_header(),
            Self::PublicKey(p) => p.write_len_with_header(),
            Self::PublicSubkey(p) => p.write_len_with_header(),
            Self::SecretKey(p) => p.write_len_with_header(),
            Self::SecretSubkey(p) => p.write_len_with_header(),
            Self::LiteralData(p) => p.write_len_with_header(),
            Self::Marker(p) => p.write_len_with_header(),
            Self::ModDetectionCode(p) => p.write_len_with_header(),
            Self::OnePassSignature(p) => p.write_len_with_header(),
            Self::PublicKeyEncryptedSessionKey(p) => p.write_len_with_header(),
            Self::Signature(p) => p.write_len_with_header(),
            Self::SymEncryptedData(p) => p.write_len_with_header(),
            Self::SymEncryptedProtectedData(p) => p.write_len_with_header(),
            Self::SymKeyEncryptedSessionKey(p) => p.write_len_with_header(),
            Self::Trust(p) => p.write_len_with_header(),
            Self::UserAttribute(p) => p.write_len_with_header(),
            Self::UserId(p) => p.write_len_with_header(),
            Self::Padding(p) => p.write_len_with_header(),
        }
    }
}

pub trait PacketTrait: Serialize {
    fn packet_header(&self) -> &PacketHeader;
    fn packet_header_version(&self) -> PacketHeaderVersion {
        self.packet_header().version()
    }
    fn tag(&self) -> Tag {
        self.packet_header().tag()
    }

    /// Write this packet including the packet header.
    fn to_writer_with_header<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        // header
        let original_header = self.packet_header();

        // If a fixed or partial len we always write out a normalized version of the header,
        // to match the encoding we generate.
        match original_header.packet_length().maybe_len() {
            Some(len) => {
                let write_len = self.write_len().try_into()?;
                let header = PacketHeader::from_parts(
                    original_header.version(),
                    original_header.tag(),
                    PacketLength::Fixed(write_len),
                )?;

                if len != write_len {
                    warn!(
                        "packet header mismatch between reading and writing: original: {:?}, generated: {:?}",
                        original_header,
                        header
                    );
                }
                header.to_writer(writer)?;
            }
            None => {
                // Indeterminate length
                original_header.to_writer(writer)?;
            }
        }

        // the actual packet body
        self.to_writer(writer)?;

        Ok(())
    }

    /// Length in bytes used when calling `to_writer_with_header`.
    fn write_len_with_header(&self) -> usize {
        let mut sum = self.packet_header().write_len();
        sum += self.write_len();
        sum
    }
}

impl PacketTrait for Packet {
    fn packet_header(&self) -> &PacketHeader {
        match self {
            Self::CompressedData(p) => p.packet_header(),
            Self::PublicKey(p) => p.packet_header(),
            Self::PublicSubkey(p) => p.packet_header(),
            Self::SecretKey(p) => p.packet_header(),
            Self::SecretSubkey(p) => p.packet_header(),
            Self::LiteralData(p) => p.packet_header(),
            Self::Marker(p) => p.packet_header(),
            Self::ModDetectionCode(p) => p.packet_header(),
            Self::OnePassSignature(p) => p.packet_header(),
            Self::PublicKeyEncryptedSessionKey(p) => p.packet_header(),
            Self::Signature(p) => p.packet_header(),
            Self::SymEncryptedData(p) => p.packet_header(),
            Self::SymEncryptedProtectedData(p) => p.packet_header(),
            Self::SymKeyEncryptedSessionKey(p) => p.packet_header(),
            Self::Trust(p) => p.packet_header(),
            Self::UserAttribute(p) => p.packet_header(),
            Self::UserId(p) => p.packet_header(),
            Self::Padding(p) => p.packet_header(),
        }
    }
}

impl<'a, T: 'a + PacketTrait> PacketTrait for &'a T {
    fn packet_header(&self) -> &PacketHeader {
        (*self).packet_header()
    }
}
