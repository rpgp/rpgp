use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::RngCore;
use smallvec::SmallVec;

use crate::{
    composed::SignedKeyDetails,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::Result,
    packet::{
        Features, KeyFlags, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData,
        UserAttribute, UserId,
    },
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
};

/// This specifies associated user id and attribute components, plus some metadata for producing
/// a [crate::composed::SignedSecretKey].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyDetails {
    primary_user_id: Option<UserId>,
    non_primary_user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    keyflags: KeyFlags,
    features: Features,
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
}

impl KeyDetails {
    #[allow(clippy::too_many_arguments)] // FIXME
    pub fn new(
        primary_user_id: Option<UserId>,
        user_ids: Vec<UserId>,
        user_attributes: Vec<UserAttribute>,
        keyflags: KeyFlags,
        features: Features,
        preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
        preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
        preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
        preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
    ) -> Self {
        KeyDetails {
            primary_user_id,
            non_primary_user_ids: user_ids,
            user_attributes,
            keyflags,
            features,
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            preferred_aead_algorithms,
        }
    }

    pub fn sign<R, K, P>(
        self,
        rng: &mut R,
        key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedKeyDetails>
    where
        R: CryptoRng + RngCore + ?Sized,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let subpackets_with_metadata = || -> Result<Vec<Subpacket>> {
            Ok(vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                ))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
                Subpacket::regular(SubpacketData::KeyFlags(self.keyflags.clone()))?,
                Subpacket::regular(SubpacketData::Features(self.features.clone()))?,
                Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
                    self.preferred_symmetric_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
                    self.preferred_hash_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
                    self.preferred_compression_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(
                    self.preferred_aead_algorithms.clone(),
                ))?,
            ])
        };

        let basic_subpackets = || -> Result<Vec<Subpacket>> {
            Ok(vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                ))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            ])
        };

        // --- Direct key signatures
        let direct_signatures = if key.version() == KeyVersion::V6 {
            let mut config =
                SignatureConfig::v6(rng, SignatureType::Key, key.algorithm(), key.hash_alg())?;
            config.hashed_subpackets = subpackets_with_metadata()?;

            let dks = config.sign_key(key, key_pw, pub_key)?;

            vec![dks]
        } else {
            vec![]
        };

        // --- User IDs
        let mut users = vec![];

        if let Some(primary_user_id) = self.primary_user_id {
            let mut config = SignatureConfig::from_key(rng, key, SignatureType::CertGeneric)?;

            config.hashed_subpackets = match key.version() {
                KeyVersion::V6 => basic_subpackets()?,
                _ => subpackets_with_metadata()?,
            };

            config
                .hashed_subpackets
                .push(Subpacket::regular(SubpacketData::IsPrimary(true))?);

            if key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets =
                    vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];
            }

            let sig = config.sign_certification(
                key,
                pub_key,
                key_pw,
                primary_user_id.tag(),
                &primary_user_id,
            )?;

            users.push(primary_user_id.into_signed(sig));
        }

        // non-primary user ids
        users.extend(
            self.non_primary_user_ids
                .into_iter()
                .map(|id| {
                    let mut config =
                        SignatureConfig::from_key(rng, key, SignatureType::CertGeneric)?;

                    config.hashed_subpackets = match key.version() {
                        KeyVersion::V6 => basic_subpackets()?,
                        _ => subpackets_with_metadata()?,
                    };

                    if key.version() <= KeyVersion::V4 {
                        config.unhashed_subpackets =
                            vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];
                    }

                    let sig = config.sign_certification(key, pub_key, key_pw, id.tag(), &id)?;

                    Ok(id.into_signed(sig))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        // --- User Attributes
        let user_attributes = self
            .user_attributes
            .into_iter()
            .map(|u| u.sign(rng, key, pub_key, key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures,
            users,
            user_attributes,
        })
    }
}
