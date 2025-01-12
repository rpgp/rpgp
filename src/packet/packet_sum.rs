use std::io;

use log::debug;

use crate::errors::Result;
use crate::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, Padding, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use crate::ser::Serialize;
use crate::types::{Tag, Version};
use crate::util::write_packet_length_len;

use super::PacketHeader;

/// Represents a Packet. A packet is the record structure used to encode a chunk of data in OpenPGP.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-syntax>
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet {
    /// The header of the packet.
    header: PacketHeader,
    /// The raw bytes of the packet
    body: PacketBody,
}

impl Packet {
    pub fn from_parts(header: PacketHeader, body: PacketBody) -> Result<Self> {
        ensure_eq!(header.tag(), body.tag(), "missmatching tags");
        ensure_eq!(
            header.version(),
            body.packet_version(),
            "missmatching packet versions"
        );

        Ok(Self { header, body })
    }

    pub fn tag(&self) -> Tag {
        self.header.tag()
    }

    pub fn packet_version(&self) -> Version {
        self.header.version()
    }

    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    pub fn body(&self) -> &PacketBody {
        &self.body
    }

    pub fn into_parts(self) -> (PacketHeader, PacketBody) {
        let Self { header, body } = self;
        (header, body)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: fix me
pub enum PacketBody {
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

impl PacketBody {
    /// Returns the tag for this packet type.
    pub const fn tag(&self) -> Tag {
        match self {
            Self::CompressedData(_) => Tag::CompressedData,
            Self::PublicKey(_) => Tag::PublicKey,
            Self::PublicSubkey(_) => Tag::PublicSubkey,
            Self::SecretKey(_) => Tag::SecretKey,
            Self::SecretSubkey(_) => Tag::SecretSubkey,
            Self::LiteralData(_) => Tag::LiteralData,
            Self::Marker(_) => Tag::Marker,
            Self::ModDetectionCode(_) => Tag::ModDetectionCode,
            Self::OnePassSignature(_) => Tag::OnePassSignature,
            Self::PublicKeyEncryptedSessionKey(_) => Tag::PublicKeyEncryptedSessionKey,
            Self::Signature(_) => Tag::Signature,
            Self::SymEncryptedData(_) => Tag::SymEncryptedData,
            Self::SymEncryptedProtectedData(_) => Tag::SymEncryptedProtectedData,
            Self::SymKeyEncryptedSessionKey(_) => Tag::SymKeyEncryptedSessionKey,
            Self::Trust(_) => Tag::Trust,
            Self::UserAttribute(_) => Tag::UserAttribute,
            Self::UserId(_) => Tag::UserId,
            Self::Padding(_) => Tag::Padding,
        }
    }

    pub fn packet_version(&self) -> Version {
        match self {
            Self::CompressedData(p) => p.packet_version(),
            Self::PublicKey(p) => p.packet_version(),
            Self::PublicSubkey(p) => p.packet_version(),
            Self::SecretKey(p) => p.packet_version(),
            Self::SecretSubkey(p) => p.packet_version(),
            Self::LiteralData(p) => p.packet_version(),
            Self::Marker(p) => p.packet_version(),
            Self::ModDetectionCode(p) => p.packet_version(),
            Self::OnePassSignature(p) => p.packet_version(),
            Self::PublicKeyEncryptedSessionKey(p) => p.packet_version(),
            Self::Signature(p) => p.packet_version(),
            Self::SymEncryptedData(p) => p.packet_version(),
            Self::SymEncryptedProtectedData(p) => p.packet_version(),
            Self::SymKeyEncryptedSessionKey(p) => p.packet_version(),
            Self::Trust(p) => p.packet_version(),
            Self::UserAttribute(p) => p.packet_version(),
            Self::UserId(p) => p.packet_version(),
            Self::Padding(p) => p.packet_version(),
        }
    }
}

impl_try_from_into!(
    PacketBody,
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

// TODO: move to its own file
impl Serialize for PacketBody {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::CompressedData(p) => write_packet(writer, &p),
            Self::PublicKey(p) => write_packet(writer, &p),
            Self::PublicSubkey(p) => write_packet(writer, &p),
            Self::SecretKey(p) => write_packet(writer, &p),
            Self::SecretSubkey(p) => write_packet(writer, &p),
            Self::LiteralData(p) => write_packet(writer, &p),
            Self::Marker(p) => write_packet(writer, &p),
            Self::ModDetectionCode(p) => write_packet(writer, &p),
            Self::OnePassSignature(p) => write_packet(writer, &p),
            Self::PublicKeyEncryptedSessionKey(p) => write_packet(writer, &p),
            Self::Signature(p) => write_packet(writer, &p),
            Self::SymEncryptedData(p) => write_packet(writer, &p),
            Self::SymEncryptedProtectedData(p) => write_packet(writer, &p),
            Self::SymKeyEncryptedSessionKey(p) => write_packet(writer, &p),
            Self::Trust(p) => write_packet(writer, &p),
            Self::UserAttribute(p) => write_packet(writer, &p),
            Self::UserId(p) => write_packet(writer, &p),
            Self::Padding(p) => write_packet(writer, &p),
        }
    }

    fn write_len(&self) -> usize {
        let len = match self {
            Self::CompressedData(p) => p.write_len(),
            Self::PublicKey(p) => p.write_len(),
            Self::PublicSubkey(p) => p.write_len(),
            Self::SecretKey(p) => p.write_len(),
            Self::SecretSubkey(p) => p.write_len(),
            Self::LiteralData(p) => p.write_len(),
            Self::Marker(p) => p.write_len(),
            Self::ModDetectionCode(p) => p.write_len(),
            Self::OnePassSignature(p) => p.write_len(),
            Self::PublicKeyEncryptedSessionKey(p) => p.write_len(),
            Self::Signature(p) => p.write_len(),
            Self::SymEncryptedData(p) => p.write_len(),
            Self::SymEncryptedProtectedData(p) => p.write_len(),
            Self::SymKeyEncryptedSessionKey(p) => p.write_len(),
            Self::Trust(p) => p.write_len(),
            Self::UserAttribute(p) => p.write_len(),
            Self::UserId(p) => p.write_len(),
            Self::Padding(p) => p.write_len(),
        };

        let mut sum = write_packet_length_len(len);
        sum += len;
        sum
    }
}

pub trait PacketTrait: Serialize {
    fn packet_version(&self) -> Version;
    fn tag(&self) -> Tag;
}

impl<'a, T: 'a + PacketTrait> PacketTrait for &'a T {
    fn packet_version(&self) -> Version {
        (*self).packet_version()
    }

    fn tag(&self) -> Tag {
        (*self).tag()
    }
}

pub fn write_packet(writer: &mut impl io::Write, packet: &impl PacketTrait) -> Result<()> {
    let packet_version = packet.packet_version();
    let packet_len = packet.write_len();
    debug!(
        "write_packet {:?} {:?} (len: {})",
        &packet_version,
        packet.tag(),
        packet_len,
    );

    // header
    packet_version.write_header(writer, packet.tag(), packet_len)?;

    // the actual packet body
    packet.to_writer(writer)?;

    Ok(())
}
