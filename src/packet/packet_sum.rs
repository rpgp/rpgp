use packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use types::Tag;

#[derive(Debug)]
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
