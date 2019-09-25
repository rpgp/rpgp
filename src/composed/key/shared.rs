use chrono::{self, SubsecRound};
use smallvec::SmallVec;

use crate::composed::SignedKeyDetails;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    KeyFlags, PacketTrait, SignatureConfigBuilder, SignatureType, Subpacket, UserAttribute, UserId,
};
use crate::types::{CompressionAlgorithm, RevocationKey, SecretKeyTrait};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyDetails {
    primary_user_id: UserId,
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    keyflags: KeyFlags,
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    revocation_key: Option<RevocationKey>,
}

impl KeyDetails {
    #[allow(clippy::too_many_arguments)] // FIXME
    pub fn new(
        primary_user_id: UserId,
        user_ids: Vec<UserId>,
        user_attributes: Vec<UserAttribute>,
        keyflags: KeyFlags,
        preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
        preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
        preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
        revocation_key: Option<RevocationKey>,
    ) -> Self {
        KeyDetails {
            primary_user_id,
            user_ids,
            user_attributes,
            keyflags,
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            revocation_key,
        }
    }

    pub fn sign<F>(self, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedKeyDetails>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let keyflags: SmallVec<[u8; 1]> = self.keyflags.into();
        let preferred_symmetric_algorithms = self.preferred_symmetric_algorithms;
        let preferred_hash_algorithms = self.preferred_hash_algorithms;
        let preferred_compression_algorithms = self.preferred_compression_algorithms;
        let revocation_key = self.revocation_key;

        let mut users = vec![];

        // primary user id
        {
            let id = self.primary_user_id;
            let mut hashed_subpackets = vec![
                Subpacket::IsPrimary(true),
                Subpacket::SignatureCreationTime(chrono::Utc::now().trunc_subsecs(0)),
                Subpacket::KeyFlags(keyflags.clone()),
                Subpacket::PreferredSymmetricAlgorithms(preferred_symmetric_algorithms.clone()),
                Subpacket::PreferredHashAlgorithms(preferred_hash_algorithms.clone()),
                Subpacket::PreferredCompressionAlgorithms(preferred_compression_algorithms.clone()),
                Subpacket::IssuerFingerprint(
                    Default::default(),
                    SmallVec::from_slice(&key.fingerprint()),
                ),
            ];
            if let Some(rkey) = revocation_key {
                hashed_subpackets.push(Subpacket::RevocationKey(rkey));
            }

            let config = SignatureConfigBuilder::default()
                .typ(SignatureType::CertGeneric)
                .pub_alg(key.algorithm())
                .hashed_subpackets(hashed_subpackets)
                .unhashed_subpackets(vec![Subpacket::Issuer(key.key_id())])
                .build()?;

            let sig = config.sign_certificate(key, key_pw.clone(), id.tag(), &id)?;

            users.push(id.into_signed(sig));
        }

        // othe user ids

        users.extend(
            self.user_ids
                .into_iter()
                .map(|id| {
                    let config = SignatureConfigBuilder::default()
                        .typ(SignatureType::CertGeneric)
                        .pub_alg(key.algorithm())
                        .hashed_subpackets(vec![
                            Subpacket::SignatureCreationTime(chrono::Utc::now().trunc_subsecs(0)),
                            Subpacket::KeyFlags(keyflags.clone()),
                            Subpacket::PreferredSymmetricAlgorithms(
                                preferred_symmetric_algorithms.clone(),
                            ),
                            Subpacket::PreferredHashAlgorithms(preferred_hash_algorithms.clone()),
                            Subpacket::PreferredCompressionAlgorithms(
                                preferred_compression_algorithms.clone(),
                            ),
                            Subpacket::IssuerFingerprint(
                                Default::default(),
                                SmallVec::from_slice(&key.fingerprint()),
                            ),
                        ])
                        .unhashed_subpackets(vec![Subpacket::Issuer(key.key_id())])
                        .build()?;

                    let sig = config.sign_certificate(key, key_pw.clone(), id.tag(), &id)?;

                    Ok(id.into_signed(sig))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let user_attributes = self
            .user_attributes
            .into_iter()
            .map(|u| u.sign(key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures: Default::default(),
            users,
            user_attributes,
        })
    }
}
