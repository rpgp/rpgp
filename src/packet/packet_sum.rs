use std::io;

use errors::Result;
use packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use ser::Serialize;
use types::{Tag, Version};

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
        let packet_version = self.packet_version();

        let mut buf = Vec::new();
        match self {
            // Packet::CompressedData(p) => p.to_writer(&mut buf)?,
            Packet::PublicKey(p) => p.to_writer(&mut buf)?,
            Packet::PublicSubkey(p) => p.to_writer(&mut buf)?,
            Packet::SecretKey(p) => p.to_writer(&mut buf)?,
            Packet::SecretSubkey(p) => p.to_writer(&mut buf)?,
            Packet::LiteralData(p) => p.to_writer(&mut buf)?,
            // Packet::Marker(p) => p.to_writer(&mut buf)?,
            // Packet::ModDetectionCode(p) => p.to_writer(&mut buf)?,
            // Packet::OnePassSignature(p) => p.to_writer(&mut buf)?,
            // Packet::PublicKeyEncryptedSessionKey(p) => p.to_writer(&mut buf)?,
            Packet::Signature(p) => p.to_writer(&mut buf)?,
            // Packet::SymEncryptedData(p) => p.to_writer(&mut buf)?,
            // Packet::SymEncryptedProtectedData(p) => p.to_writer(&mut buf)?,
            // Packet::SymKeyEncryptedSessionKey(p) => p.to_writer(&mut buf)?,
            // Packet::Trust(p) => p.to_writer(&mut buf)?,
            Packet::UserAttribute(p) => p.to_writer(&mut buf)?,
            Packet::UserId(p) => p.to_writer(&mut buf)?,
            _ => unimplemented_err!("serialization for {:?}", self.tag()),
        }

        // header
        packet_version.write_header(writer, self.tag() as u8, buf.len())?;

        // the actual packet body
        info!("buf: {}", hex::encode(&buf));
        writer.write_all(&buf)?;

        Ok(())
    }
}
