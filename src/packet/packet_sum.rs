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
        // TODO: return tag
        unimplemented!()
    }
}

macro_rules! impl_try_from_into {
    ($enum_name:ident, $( $name:ident => $variant_type:ty ),*) => {
       $(
           impl $crate::try_from::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Err = ();

               fn try_from(other: $enum_name) -> Result<$variant_type, Self::Err> {
                   if let $enum_name::$name(value) = other {
                       Ok(value)
                   } else {
                       Err(())
                   }
               }
           }

           impl From<$variant_type> for $enum_name {
               fn from(other: $variant_type) -> $enum_name {
                   $enum_name::$name(other)
               }
           }
       )*
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
