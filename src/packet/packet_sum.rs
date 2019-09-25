use std::io;

use crate::errors::Result;
use crate::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use crate::ser::Serialize;
use crate::types::{Tag, Version};

#[derive(Debug)]
#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))] // TODO: fix me
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
}

impl Packet {
    /// Returns the tag for this packet type.
    pub fn tag(&self) -> Tag {
        match self {
            Packet::CompressedData(_) => Tag::CompressedData,
            Packet::PublicKey(_) => Tag::PublicKey,
            Packet::PublicSubkey(_) => Tag::PublicSubkey,
            Packet::SecretKey(_) => Tag::SecretKey,
            Packet::SecretSubkey(_) => Tag::SecretSubkey,
            Packet::LiteralData(_) => Tag::LiteralData,
            Packet::Marker(_) => Tag::Marker,
            Packet::ModDetectionCode(_) => Tag::ModDetectionCode,
            Packet::OnePassSignature(_) => Tag::OnePassSignature,
            Packet::PublicKeyEncryptedSessionKey(_) => Tag::PublicKeyEncryptedSessionKey,
            Packet::Signature(_) => Tag::Signature,
            Packet::SymEncryptedData(_) => Tag::SymEncryptedData,
            Packet::SymEncryptedProtectedData(_) => Tag::SymEncryptedProtectedData,
            Packet::SymKeyEncryptedSessionKey(_) => Tag::SymKeyEncryptedSessionKey,
            Packet::Trust(_) => Tag::Trust,
            Packet::UserAttribute(_) => Tag::UserAttribute,
            Packet::UserId(_) => Tag::UserId,
        }
    }

    pub fn packet_version(&self) -> Version {
        match self {
            Packet::CompressedData(p) => p.packet_version(),
            Packet::PublicKey(p) => p.packet_version(),
            Packet::PublicSubkey(p) => p.packet_version(),
            Packet::SecretKey(p) => p.packet_version(),
            Packet::SecretSubkey(p) => p.packet_version(),
            Packet::LiteralData(p) => p.packet_version(),
            Packet::Marker(p) => p.packet_version(),
            Packet::ModDetectionCode(p) => p.packet_version(),
            Packet::OnePassSignature(p) => p.packet_version(),
            Packet::PublicKeyEncryptedSessionKey(p) => p.packet_version(),
            Packet::Signature(p) => p.packet_version(),
            Packet::SymEncryptedData(p) => p.packet_version(),
            Packet::SymEncryptedProtectedData(p) => p.packet_version(),
            Packet::SymKeyEncryptedSessionKey(p) => p.packet_version(),
            Packet::Trust(p) => p.packet_version(),
            Packet::UserAttribute(p) => p.packet_version(),
            Packet::UserId(p) => p.packet_version(),
        }
    }
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
    UserId => UserId
);

// TODO: move to its own file
impl Serialize for Packet {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Packet::CompressedData(p) => write_packet(writer, &p),
            Packet::PublicKey(p) => write_packet(writer, &p),
            Packet::PublicSubkey(p) => write_packet(writer, &p),
            Packet::SecretKey(p) => write_packet(writer, &p),
            Packet::SecretSubkey(p) => write_packet(writer, &p),
            Packet::LiteralData(p) => write_packet(writer, &p),
            Packet::Marker(p) => write_packet(writer, &p),
            Packet::ModDetectionCode(p) => write_packet(writer, &p),
            Packet::OnePassSignature(p) => write_packet(writer, &p),
            Packet::PublicKeyEncryptedSessionKey(p) => write_packet(writer, &p),
            Packet::Signature(p) => write_packet(writer, &p),
            Packet::SymEncryptedData(p) => write_packet(writer, &p),
            Packet::SymEncryptedProtectedData(p) => write_packet(writer, &p),
            Packet::SymKeyEncryptedSessionKey(p) => write_packet(writer, &p),
            Packet::Trust(p) => write_packet(writer, &p),
            Packet::UserAttribute(p) => write_packet(writer, &p),
            Packet::UserId(p) => write_packet(writer, &p),
        }
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
    let mut buf = Vec::new();
    packet.to_writer(&mut buf)?;
    info!(
        "write_packet {:?} {:?} (len: {})",
        &packet_version,
        packet.tag(),
        buf.len()
    );

    // header
    packet_version.write_header(writer, packet.tag() as u8, buf.len())?;

    // the actual packet body
    writer.write_all(&buf)?;

    Ok(())
}
