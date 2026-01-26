use std::io;

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
    packet::{Features, KeyFlags, PacketTrait, SignatureVersion},
    ser::Serialize,
    types::{PacketLength, SignedUser, SignedUserAttribute, VerifyingKey},
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

    fn verify_users<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        for user in &self.users {
            user.verify_bindings(key)?;
        }

        Ok(())
    }

    fn verify_attributes<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        for attr in &self.user_attributes {
            attr.verify_bindings(key)?;
        }

        Ok(())
    }

    fn verify_revocation_signatures<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        for sig in &self.revocation_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    fn verify_direct_signatures<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        for sig in &self.direct_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    pub fn verify_bindings<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        self.verify_users(key)?;
        self.verify_attributes(key)?;
        self.verify_revocation_signatures(key)?;
        self.verify_direct_signatures(key)?;

        Ok(())
    }

    /// Derive a `KeyDetails` from a `SignedKeyDetails`.
    /// This is more of a heuristic than a surefire transformation.
    ///
    /// Note: this is also not checking the cryptographic validity of the signatures it's
    /// evaluating, and e.g. not trying to find the newest signature of each type.
    /// This whole functions is an optimistic heuristic, not a rigorous evaluation.
    ///
    /// Don't rely too hard on its outputs!
    pub fn as_unsigned(&self) -> KeyDetails {
        // Let's try to figure out if this SignedKeyDetails appears to belong to a v6 key, or a
        // previous generation (this information is not explicitly encoded in self, so we're
        // looking around, and half guessing).
        let probably_v6 = if let Some(first) = self.direct_signatures.first() {
            if first.version() == SignatureVersion::V6 {
                // has a DKS, and it's v6, so yes
                true
            } else {
                // has a DKS, and it's not v6, so no
                false
            }
        } else {
            // this might still be a key with v6 parts, but without a DKS, it's not a valid one
            false
        };

        if probably_v6 {
            // we expect the data on a dks
            let first_dks = self
                .direct_signatures
                .first()
                .expect("we checked this above");

            let keyflags = first_dks.key_flags();
            let features = first_dks.features();

            let preferred_symmetric_algorithms =
                SmallVec::from_slice(first_dks.preferred_symmetric_algs());
            let preferred_hash_algorithms = SmallVec::from_slice(first_dks.preferred_hash_algs());
            let preferred_compression_algorithms =
                SmallVec::from_slice(first_dks.preferred_compression_algs());
            let preferred_aead_algorithms = SmallVec::from_slice(first_dks.preferred_aead_algs());

            let primary_user = self
                .users
                .iter()
                .find(|u| u.is_primary())
                .map_or_else(|| self.users.first(), Some);

            KeyDetails::new(
                primary_user.map(|su| su.id.clone()),
                self.users
                    .iter()
                    .filter_map(|u| {
                        if Some(&u.id) == primary_user.map(|pri_su| &pri_su.id) {
                            None // drop the primary
                        } else {
                            Some(u.id.clone())
                        }
                    })
                    .collect(),
                self.user_attributes
                    .iter()
                    .map(|a| a.attr.clone())
                    .collect(),
                keyflags,
                features.cloned().unwrap_or(Features::default()),
                preferred_symmetric_algorithms,
                preferred_hash_algorithms,
                preferred_compression_algorithms,
                preferred_aead_algorithms,
            )
        } else if let Some(primary_user) = self
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
            let features = primary_sig.features();

            let preferred_symmetric_algorithms =
                SmallVec::from_slice(primary_sig.preferred_symmetric_algs());
            let preferred_hash_algorithms = SmallVec::from_slice(primary_sig.preferred_hash_algs());
            let preferred_compression_algorithms =
                SmallVec::from_slice(primary_sig.preferred_compression_algs());
            let preferred_aead_algorithms = SmallVec::from_slice(primary_sig.preferred_aead_algs());

            KeyDetails::new(
                Some(primary_user.id.clone()),
                self.users
                    .iter()
                    .filter(|u| u.id != primary_user.id) // drop the primary
                    .map(|u| u.id.clone())
                    .collect(),
                self.user_attributes
                    .iter()
                    .map(|a| a.attr.clone())
                    .collect(),
                keyflags,
                features.cloned().unwrap_or(Features::default()),
                preferred_symmetric_algorithms,
                preferred_hash_algorithms,
                preferred_compression_algorithms,
                preferred_aead_algorithms,
            )
        } else {
            // We don't have metadata via a primary user id, so we return a very bare KeyDetails object

            // TODO: even for non-v6 keys, we could check for information in a direct key
            // signature and use that if it exists

            let mut features = Features::new();
            features.set_seipd_v1(true);

            KeyDetails::new(
                None,
                self.users.iter().map(|u| u.id.clone()).collect(),
                self.user_attributes
                    .iter()
                    .map(|a| a.attr.clone())
                    .collect(),
                KeyFlags::default(),
                features,
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

/// A wrapper that contains either a [`SignedPublicKey`] or a [`SignedSecretKey`].
#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)] // FIXME
pub enum PublicOrSecret {
    Public(SignedPublicKey),
    Secret(SignedSecretKey),
}

impl PublicOrSecret {
    pub fn verify_bindings(&self) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.verify_bindings(),
            PublicOrSecret::Secret(k) => k.verify_bindings(),
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

/// Error returned when trying to convert [`PublicOrSecret`] key
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
