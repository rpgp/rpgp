use aes_gcm::aead::rand_core::CryptoRng;
use chrono::SubsecRound;
use rand::Rng;
use smallvec::SmallVec;

use crate::composed::SignedKeyDetails;
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    KeyFlags, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserAttribute,
    UserId,
};
use crate::ser::Serialize;
use crate::types::{
    CompressionAlgorithm, KeyVersion, Password, PublicKeyTrait, RevocationKey, SecretKeyTrait,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyDetails {
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    keyflags: KeyFlags,
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
    revocation_key: Option<RevocationKey>,
}

impl KeyDetails {
    #[allow(clippy::too_many_arguments)] // FIXME
    pub fn new(
        primary_user_id: UserId,
        mut user_ids: Vec<UserId>,
        user_attributes: Vec<UserAttribute>,
        keyflags: KeyFlags,
        preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
        preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
        preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
        preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
        revocation_key: Option<RevocationKey>,
    ) -> Self {
        user_ids.insert(0, primary_user_id);

        Self::new_direct(
            user_ids,
            user_attributes,
            keyflags,
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            preferred_aead_algorithms,
            revocation_key,
        )
    }

    /// The primary UserId (if any) is expected to be contained in `user_ids`
    #[allow(clippy::too_many_arguments)] // FIXME
    pub(crate) fn new_direct(
        user_ids: Vec<UserId>,
        user_attributes: Vec<UserAttribute>,
        keyflags: KeyFlags,
        preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
        preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
        preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
        preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
        revocation_key: Option<RevocationKey>,
    ) -> Self {
        KeyDetails {
            user_ids,
            user_attributes,
            keyflags,
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            preferred_aead_algorithms,
            revocation_key,
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
        let keyflags: SmallVec<[u8; 1]> = self.keyflags.into();
        let preferred_symmetric_algorithms = self.preferred_symmetric_algorithms;
        let preferred_hash_algorithms = self.preferred_hash_algorithms;
        let preferred_compression_algorithms = self.preferred_compression_algorithms;
        let preferred_aead_algorithms = self.preferred_aead_algorithms;
        let revocation_key = self.revocation_key;

        let mut users = vec![];

        // We consider the first entry in `user_ids` (if any) the primary user id
        // FIXME: select primary like in signed_key/shared.rs:116? (and adjust the set of non-primaries below?)
        if let Some(id) = self.user_ids.first() {
            let mut hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::IsPrimary(true))?,
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                ))?,
                Subpacket::regular(SubpacketData::KeyFlags(keyflags.clone()))?,
                Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
                    preferred_symmetric_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
                    preferred_hash_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
                    preferred_compression_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(
                    preferred_aead_algorithms.clone(),
                ))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            ];
            if let Some(rkey) = revocation_key {
                hashed_subpackets.push(Subpacket::regular(SubpacketData::RevocationKey(rkey))?);
            }

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

            config.hashed_subpackets = hashed_subpackets;
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];

            let sig = config.sign_certification(key, pub_key, key_pw, id.tag(), &id)?;

            users.push(id.clone().into_signed(sig));
        }

        // other user ids

        users.extend(
            self.user_ids
                .into_iter()
                .skip(1) // The first User ID was handled above, as the primary user id
                .map(|id| {
                    let hashed_subpackets = vec![
                        Subpacket::regular(SubpacketData::SignatureCreationTime(
                            chrono::Utc::now().trunc_subsecs(0),
                        ))?,
                        Subpacket::regular(SubpacketData::KeyFlags(keyflags.clone()))?,
                        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
                            preferred_symmetric_algorithms.clone(),
                        ))?,
                        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
                            preferred_hash_algorithms.clone(),
                        ))?,
                        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
                            preferred_compression_algorithms.clone(),
                        ))?,
                        Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(
                            preferred_aead_algorithms.clone(),
                        ))?,
                        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
                    ];
                    let unhashed_subpackets =
                        vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];

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

                    config.hashed_subpackets = hashed_subpackets;
                    config.unhashed_subpackets = unhashed_subpackets;

                    let sig = config.sign_certification(key, pub_key, key_pw, id.tag(), &id)?;

                    Ok(id.into_signed(sig))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let user_attributes = self
            .user_attributes
            .into_iter()
            .map(|u| u.sign(&mut rng, key, pub_key, key_pw))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures: Default::default(),
            users,
            user_attributes,
        })
    }
}
