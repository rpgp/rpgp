use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use chrono::{DateTime, Duration, Utc};
use smallvec::SmallVec;

use crate::crypto::{
    aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
    sym::SymmetricKeyAlgorithm,
};
use crate::errors::Result;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{CompressionAlgorithm, Fingerprint, KeyId, RevocationKey};

use super::{Notation, RevocationCode, Signature};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Available signature subpacket types
pub enum SubpacketType {
    SignatureCreationTime,
    SignatureExpirationTime,
    ExportableCertification,
    TrustSignature,
    RegularExpression,
    Revocable,
    KeyExpirationTime,
    PreferredSymmetricAlgorithms,
    RevocationKey,
    Issuer,
    Notation,
    PreferredHashAlgorithms,
    PreferredCompressionAlgorithms,
    KeyServerPreferences,
    PreferredKeyServer,
    PrimaryUserId,
    PolicyURI,
    KeyFlags,
    SignersUserID,
    RevocationReason,
    Features,
    SignatureTarget,
    EmbeddedSignature,
    IssuerFingerprint,
    PreferredEncryptionModes, // non-RFC, may only be 1: EAX, 2: OCB
    IntendedRecipientFingerprint,
    // AttestedCertifications, // non-RFC
    // KeyBlock,               // non-RFC
    PreferredAead,
    Experimental(u8),
    Other(u8),
}

impl SubpacketType {
    pub fn as_u8(&self, is_critical: bool) -> u8 {
        let raw: u8 = match self {
            SubpacketType::SignatureCreationTime => 2,
            SubpacketType::SignatureExpirationTime => 3,
            SubpacketType::ExportableCertification => 4,
            SubpacketType::TrustSignature => 5,
            SubpacketType::RegularExpression => 6,
            SubpacketType::Revocable => 7,
            SubpacketType::KeyExpirationTime => 9,
            SubpacketType::PreferredSymmetricAlgorithms => 11,
            SubpacketType::RevocationKey => 12,
            SubpacketType::Issuer => 16,
            SubpacketType::Notation => 20,
            SubpacketType::PreferredHashAlgorithms => 21,
            SubpacketType::PreferredCompressionAlgorithms => 22,
            SubpacketType::KeyServerPreferences => 23,
            SubpacketType::PreferredKeyServer => 24,
            SubpacketType::PrimaryUserId => 25,
            SubpacketType::PolicyURI => 26,
            SubpacketType::KeyFlags => 27,
            SubpacketType::SignersUserID => 28,
            SubpacketType::RevocationReason => 29,
            SubpacketType::Features => 30,
            SubpacketType::SignatureTarget => 31,
            SubpacketType::EmbeddedSignature => 32,
            SubpacketType::IssuerFingerprint => 33,
            SubpacketType::PreferredEncryptionModes => 34,
            SubpacketType::IntendedRecipientFingerprint => 35,
            // SubpacketType::AttestedCertifications => 37,
            // SubpacketType::KeyBlock => 38,
            SubpacketType::PreferredAead => 39,
            SubpacketType::Experimental(n) => *n,
            SubpacketType::Other(n) => *n,
        };

        if is_critical {
            // set critical bit
            raw | 0b1000_0000
        } else {
            raw
        }
    }

    #[inline]
    pub fn from_u8(n: u8) -> (Self, bool) {
        let is_critical = (n >> 7) == 1;
        // remove critical bit
        let n = n & 0b0111_1111;

        let m = match n {
            2 => SubpacketType::SignatureCreationTime,
            3 => SubpacketType::SignatureExpirationTime,
            4 => SubpacketType::ExportableCertification,
            5 => SubpacketType::TrustSignature,
            6 => SubpacketType::RegularExpression,
            7 => SubpacketType::Revocable,
            9 => SubpacketType::KeyExpirationTime,
            11 => SubpacketType::PreferredSymmetricAlgorithms,
            12 => SubpacketType::RevocationKey,
            16 => SubpacketType::Issuer,
            20 => SubpacketType::Notation,
            21 => SubpacketType::PreferredHashAlgorithms,
            22 => SubpacketType::PreferredCompressionAlgorithms,
            23 => SubpacketType::KeyServerPreferences,
            24 => SubpacketType::PreferredKeyServer,
            25 => SubpacketType::PrimaryUserId,
            26 => SubpacketType::PolicyURI,
            27 => SubpacketType::KeyFlags,
            28 => SubpacketType::SignersUserID,
            29 => SubpacketType::RevocationReason,
            30 => SubpacketType::Features,
            31 => SubpacketType::SignatureTarget,
            32 => SubpacketType::EmbeddedSignature,
            33 => SubpacketType::IssuerFingerprint,
            34 => SubpacketType::PreferredEncryptionModes,
            35 => SubpacketType::IntendedRecipientFingerprint,
            // 37 => SubpacketType::AttestedCertifications,
            // 38 => SubpacketType::KeyBlock,
            39 => SubpacketType::PreferredAead,
            100..=110 => SubpacketType::Experimental(n),
            _ => SubpacketType::Other(n),
        };

        (m, is_critical)
    }
}

/// Represents a subpack length.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-subpacket-specifi>
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum SubpacketLength {
    /// 1 byte encoding, must be less than `192`.
    One(#[cfg_attr(test, proptest(strategy = "0u8..=191"))] u8),
    /// 2 byte encoding
    Two(#[cfg_attr(test, proptest(strategy = "192u16..=254"))] u16),
    /// 4 byte encoding
    Five(#[cfg_attr(test, proptest(strategy = "255u32.."))] u32),
}

impl SubpacketLength {
    /// Parses a supbacket length from the given buffer.
    pub(crate) fn from_buf<B: Buf>(mut i: B) -> Result<Self> {
        let olen = i.read_u8()?;
        let len = match olen {
            // One-Octet Lengths
            0..=191 => Self::One(olen),
            // Two-Octet Lengths
            192..=254 => {
                let a = i.read_u8()?;
                let l = ((olen as u16 - 192) << 8) + 192 + a as u16;
                Self::Two(l)
            }
            255 => {
                let len = i.read_be_u32()?;
                Self::Five(len)
            }
        };
        Ok(len)
    }

    /// Encodes the given length into a minimal version
    pub(crate) fn encode(len: u32) -> Self {
        match len {
            0..=191 => Self::One(len as u8),
            192..=254 => Self::Two(len as u16),
            _ => Self::Five(len),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::One(l) => *l as _,
            Self::Two(l) => *l as _,
            Self::Five(l) => *l as _,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Serialize for SubpacketLength {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::One(l) => {
                writer.write_u8(*l)?;
            }
            Self::Two(l) => {
                writer.write_u8((((l - 192) / 256) + 192) as u8)?;
                writer.write_u8(((l - 192) % 256) as u8)?;
            }
            Self::Five(l) => {
                writer.write_u8(0xFF)?;
                writer.write_u32::<BigEndian>(*l)?
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Two(_) => 2,
            Self::Five(_) => 5,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subpacket {
    pub is_critical: bool,
    pub data: SubpacketData,
    pub len: SubpacketLength,
}

impl Subpacket {
    /// Construct a new regular subpacket.
    pub fn regular(data: SubpacketData) -> Result<Self> {
        let raw_len = (data.write_len() + 1).try_into()?;
        let len = SubpacketLength::encode(raw_len);
        Ok(Subpacket {
            is_critical: false,
            data,
            len,
        })
    }

    /// Construct a new critical subpacket.
    pub fn critical(data: SubpacketData) -> Result<Self> {
        let raw_len = (data.write_len() + 1).try_into()?;
        let len = SubpacketLength::encode(raw_len);
        Ok(Subpacket {
            is_critical: true,
            data,
            len,
        })
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum SubpacketData {
    /// The time the signature was made.
    SignatureCreationTime(DateTime<Utc>),
    /// The time the signature will expire.
    SignatureExpirationTime(Duration),
    /// When the key is going to expire
    KeyExpirationTime(Duration),
    /// The OpenPGP Key ID of the key issuing the signature.
    Issuer(KeyId),
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    /// Renamed to "Preferred Symmetric Ciphers for v1 SEIPD" in RFC 9580
    PreferredSymmetricAlgorithms(SmallVec<[SymmetricKeyAlgorithm; 8]>),
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    PreferredHashAlgorithms(SmallVec<[HashAlgorithm; 8]>),
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    PreferredCompressionAlgorithms(SmallVec<[CompressionAlgorithm; 8]>),
    KeyServerPreferences(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 4]>),
    KeyFlags(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 1]>),
    Features(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 1]>),
    RevocationReason(RevocationCode, Bytes),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(Notation),
    RevocationKey(RevocationKey),
    SignersUserID(Bytes),
    /// The URI of the policy under which the signature was issued
    PolicyURI(String),
    TrustSignature(u8, u8),
    RegularExpression(Bytes),
    ExportableCertification(bool),
    IssuerFingerprint(Fingerprint),
    PreferredEncryptionModes(SmallVec<[AeadAlgorithm; 2]>),
    IntendedRecipientFingerprint(Fingerprint),
    PreferredAeadAlgorithms(SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>),
    Experimental(u8, #[debug("{}", hex::encode(_1))] Bytes),
    Other(u8, #[debug("{}", hex::encode(_1))] Bytes),
    SignatureTarget(
        PublicKeyAlgorithm,
        HashAlgorithm,
        #[debug("{}", hex::encode(_2))] Bytes,
    ),
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn subpacket_length_write_len(len: SubpacketLength) {
            let mut buf = Vec::new();
            len.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), len.write_len());
        }


        #[test]
        fn subpacket_length_packet_roundtrip(len: SubpacketLength) {
            let mut buf = Vec::new();
            len.to_writer(&mut buf).unwrap();
            let new_len = SubpacketLength::from_buf(&mut &buf[..]).unwrap();
            assert_eq!(len, new_len);
        }
    }
}
