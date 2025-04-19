use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::Rng;
use smallvec::SmallVec;

use crate::{
    composed::SignedKeyDetails,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{unsupported_err, Result},
    packet::{
        KeyFlags, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData,
        UserAttribute, UserId,
    },
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
};

/// A KeyDetails specifies associated user id and attribute components, and some metadata for
/// producing a [SignedSecretKey].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyDetails {
    primary_user_id: Option<UserId>,
    non_primary_user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    keyflags: KeyFlags,
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
}

impl KeyDetails {
    #[allow(clippy::too_many_arguments)] // FIXME
    pub(crate) fn new(
        primary_user_id: Option<UserId>,
        user_ids: Vec<UserId>,
        user_attributes: Vec<UserAttribute>,
        keyflags: KeyFlags,
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
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            preferred_aead_algorithms,
        }
    }

    pub fn sign<R, K, P>(
        self,
        mut rng: R,
        key: &K,
        pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedKeyDetails>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        // Technically this should probably check for >= version 6, for at least
        let is_v6 = key.version() == KeyVersion::V6;

        // TODO: get features via KeyDetails?
        let features: SmallVec<[u8; 1]> = if is_v6 {
            // SEIPDv1 and SEIPDv2
            [0x01 | 0x08].into()
        } else {
            // SEIPDv1
            [0x01].into()
        };

        let subpackets_with_metadata = || -> Result<Vec<Subpacket>> {
            let mut sp = vec![
                Subpacket::critical(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                ))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
                Subpacket::critical(SubpacketData::KeyFlags(self.keyflags.clone()))?,
                Subpacket::regular(SubpacketData::Features(features.clone()))?,
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
            ];

            if !is_v6 {
                sp.push(Subpacket::regular(SubpacketData::Issuer(key.key_id()))?);
            }

            Ok(sp)
        };

        let basic_subpackets = || -> Result<Vec<Subpacket>> {
            let mut sp = vec![
                Subpacket::critical(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                ))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            ];

            if !is_v6 {
                sp.push(Subpacket::regular(SubpacketData::Issuer(key.key_id()))?);
            }

            Ok(sp)
        };

        // --- Direct key signatures
        let direct_signatures = match key.version() {
            KeyVersion::V6 => {
                let mut config = SignatureConfig::v6(
                    &mut rng,
                    SignatureType::Key,
                    key.algorithm(),
                    key.hash_alg(),
                )?;
                config.hashed_subpackets = subpackets_with_metadata()?;

                let dks = config.sign_key(key, key_pw, pub_key)?;

                vec![dks]
            }
            _ => vec![],
        };

        // --- User IDs
        let mut users = vec![];

        if let Some(primary_user_id) = self.primary_user_id {
            let mut config = match key.version() {
                KeyVersion::V4 => {
                    SignatureConfig::v4(SignatureType::CertGeneric, key.algorithm(), key.hash_alg())
                }
                KeyVersion::V6 => SignatureConfig::v6(
                    &mut rng,
                    SignatureType::CertGeneric,
                    key.algorithm(),
                    key.hash_alg(),
                )?,
                v => unsupported_err!("unsupported key version: {:?}", v),
            };

            config.hashed_subpackets = match key.version() {
                KeyVersion::V6 => basic_subpackets()?,
                _ => subpackets_with_metadata()?,
            };

            config
                .hashed_subpackets
                .push(Subpacket::regular(SubpacketData::IsPrimary(true))?);

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
                    let mut config = match key.version() {
                        KeyVersion::V4 => SignatureConfig::v4(
                            SignatureType::CertGeneric,
                            key.algorithm(),
                            key.hash_alg(),
                        ),
                        KeyVersion::V6 => SignatureConfig::v6(
                            &mut rng,
                            SignatureType::CertGeneric,
                            key.algorithm(),
                            key.hash_alg(),
                        )?,
                        v => unsupported_err!("unsupported key version: {:?}", v),
                    };

                    config.hashed_subpackets = match key.version() {
                        KeyVersion::V6 => basic_subpackets()?,
                        _ => subpackets_with_metadata()?,
                    };

                    let sig = config.sign_certification(key, pub_key, key_pw, id.tag(), &id)?;

                    Ok(id.into_signed(sig))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        // --- User Attributes
        let user_attributes = self
            .user_attributes
            .into_iter()
            .map(|u| u.sign(&mut rng, key, pub_key, key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures,
            users,
            user_attributes,
        })
    }
}
