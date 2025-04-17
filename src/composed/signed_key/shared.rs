use std::io;

use chrono::Duration;
use log::warn;
use smallvec::SmallVec;
use snafu::Snafu;

use crate::{
    composed::{
        key::KeyDetails,
        signed_key::{SignedPublicKey, SignedSecretKey},
        ArmorOptions,
    },
    errors::Result,
    packet,
    packet::{KeyFlags, PacketTrait},
    ser::Serialize,
    types::{PacketLength, PublicKeyTrait, SignedUser, SignedUserAttribute},
};

/// Shared details between secret and public keys.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedKeyDetails {
    pub revocation_signatures: Vec<packet::Signature>,
    pub direct_signatures: Vec<packet::Signature>,
    pub users: Vec<SignedUser>,
    pub user_attributes: Vec<SignedUserAttribute>,
}

impl SignedKeyDetails {
    pub fn new(
        revocation_signatures: Vec<packet::Signature>,
        direct_signatures: Vec<packet::Signature>,
        mut users: Vec<SignedUser>,
        mut user_attributes: Vec<SignedUserAttribute>,
    ) -> Self {
        users.retain(|user| {
            if user.signatures.is_empty() {
                warn!("ignoring unsigned {}", user.id);
                false
            } else {
                true
            }
        });

        user_attributes.retain(|attr| {
            if attr.signatures.is_empty() {
                warn!("ignoring unsigned {}", attr.attr);
                false
            } else {
                true
            }
        });

        SignedKeyDetails {
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
        }
    }

    /// Get the key expiration time as a duration.
    ///
    /// This method finds the signature with the maximum
    /// `KeyExpirationTime` offset (which should only occur in
    /// self-signed signatures) and converts it into a duration.
    /// The function returns `None` if the key has an infinite
    /// validity.
    pub fn key_expiration_time(&self) -> Option<Duration> {
        // Find the maximum key_expiration_time in all signatures of all user ids.
        self.users
            .iter()
            .flat_map(|user| &user.signatures)
            .filter_map(|sig| sig.key_expiration_time())
            .max()
            .cloned()
    }

    fn verify_users<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        for user in &self.users {
            user.verify(key)?;
        }

        Ok(())
    }

    fn verify_attributes<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        for attr in &self.user_attributes {
            attr.verify(key)?;
        }

        Ok(())
    }

    fn verify_revocation_signatures<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        for sig in &self.revocation_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    fn verify_direct_signatures<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        for sig in &self.direct_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    pub fn verify<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        self.verify_users(key)?;
        self.verify_attributes(key)?;
        self.verify_revocation_signatures(key)?;
        self.verify_direct_signatures(key)?;

        Ok(())
    }

    pub fn as_unsigned(&self) -> KeyDetails {
        if let Some(primary_user) = self
            .users
            .iter()
            .find(|u| u.is_primary())
            .map_or_else(|| self.users.first(), Some)
        {
            let primary_sig = primary_user
                .signatures
                .first()
                .expect("invalid primary user");
            let keyflags = primary_sig.key_flags();

            let preferred_symmetric_algorithms =
                SmallVec::from_slice(primary_sig.preferred_symmetric_algs());
            let preferred_hash_algorithms = SmallVec::from_slice(primary_sig.preferred_hash_algs());
            let preferred_compression_algorithms =
                SmallVec::from_slice(primary_sig.preferred_compression_algs());
            let preferred_aead_algorithms = SmallVec::from_slice(primary_sig.preferred_aead_algs());

            KeyDetails::new_direct(
                self.users.iter().map(|u| u.id.clone()).collect(),
                self.user_attributes
                    .iter()
                    .map(|a| a.attr.clone())
                    .collect(),
                keyflags,
                preferred_symmetric_algorithms,
                preferred_hash_algorithms,
                preferred_compression_algorithms,
                preferred_aead_algorithms,
            )
        } else {
            // We don't have metadata via a primary user id, so we return a very bare KeyDetails object

            // TODO: we could check for information in a direct key signature and use that

            KeyDetails::new_direct(
                self.users.iter().map(|u| u.id.clone()).collect(),
                self.user_attributes
                    .iter()
                    .map(|a| a.attr.clone())
                    .collect(),
                KeyFlags::default(),
                vec![].into(),
                vec![].into(),
                vec![].into(),
                vec![].into(),
            )
        }
    }
}

impl Serialize for SignedKeyDetails {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        for sig in &self.revocation_signatures {
            sig.to_writer_with_header(writer)?;
        }

        for sig in &self.direct_signatures {
            sig.to_writer_with_header(writer)?;
        }

        for user in &self.users {
            user.to_writer(writer)?;
        }

        for attr in &self.user_attributes {
            attr.to_writer(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        for sig in &self.revocation_signatures {
            let len = sig.write_len().try_into().expect("signature size");
            sum += PacketLength::fixed_encoding_len(len);
            sum += len as usize;
        }

        for sig in &self.direct_signatures {
            let len = sig.write_len().try_into().expect("signature size");
            sum += PacketLength::fixed_encoding_len(len);
            sum += len as usize;
        }

        for user in &self.users {
            sum += user.write_len();
        }

        for attr in &self.user_attributes {
            sum += attr.write_len();
        }
        sum
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)] // FIXME
pub enum PublicOrSecret {
    Public(SignedPublicKey),
    Secret(SignedSecretKey),
}

impl PublicOrSecret {
    pub fn verify(&self) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.verify(),
            PublicOrSecret::Secret(k) => k.verify(),
        }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_writer(writer, opts),
            PublicOrSecret::Secret(k) => k.to_armored_writer(writer, opts),
        }
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_bytes(opts),
            PublicOrSecret::Secret(k) => k.to_armored_bytes(opts),
        }
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_string(opts),
            PublicOrSecret::Secret(k) => k.to_armored_string(opts),
        }
    }

    /// Returns secret key.
    ///
    /// Panics if not a secret key.
    #[deprecated(note = "Can panic. Users should use TryFrom trait instead.")]
    pub fn into_secret(self) -> SignedSecretKey {
        self.try_into()
            .expect("Can not convert a public into a secret key")
    }

    /// Returns public key.
    ///
    /// Panics if not a public key.
    #[deprecated(note = "Can panic. Users should use TryFrom trait instead.")]
    pub fn into_public(self) -> SignedPublicKey {
        self.try_into()
            .expect("Can not convert a secret into a public key")
    }

    pub fn is_public(&self) -> bool {
        match self {
            PublicOrSecret::Secret(_) => false,
            PublicOrSecret::Public(_) => true,
        }
    }

    pub fn is_secret(&self) -> bool {
        match self {
            PublicOrSecret::Secret(_) => true,
            PublicOrSecret::Public(_) => false,
        }
    }
}

/// Error returned when trying to convert `PublicOrSecret` key
/// into the wrong type.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(display("Attempt to convert PublicOrSecret key to the wrong type"))]
pub struct TryFromPublicOrSecretError;

impl TryFrom<PublicOrSecret> for SignedPublicKey {
    type Error = TryFromPublicOrSecretError;

    fn try_from(public_or_secret: PublicOrSecret) -> Result<Self, Self::Error> {
        match public_or_secret {
            PublicOrSecret::Public(k) => Ok(k),
            PublicOrSecret::Secret(_) => Err(TryFromPublicOrSecretError),
        }
    }
}

impl TryFrom<PublicOrSecret> for SignedSecretKey {
    type Error = TryFromPublicOrSecretError;

    fn try_from(public_or_secret: PublicOrSecret) -> Result<Self, Self::Error> {
        match public_or_secret {
            PublicOrSecret::Public(_) => Err(TryFromPublicOrSecretError),
            PublicOrSecret::Secret(k) => Ok(k),
        }
    }
}

impl Serialize for PublicOrSecret {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.to_writer(writer),
            PublicOrSecret::Secret(k) => k.to_writer(writer),
        }
    }

    fn write_len(&self) -> usize {
        match self {
            PublicOrSecret::Public(k) => k.write_len(),
            PublicOrSecret::Secret(k) => k.write_len(),
        }
    }
}
