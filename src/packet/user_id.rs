use std::{fmt, io, str};

use aes_gcm::aead::rand_core::CryptoRng;
use bstr::{BStr, BString};
use chrono::{SubsecRound, Utc};
use rand::Rng;

use crate::errors::Result;
use crate::packet::{
    PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use crate::ser::Serialize;
use crate::types::{KeyVersion, PublicKeyTrait, SecretKeyTrait, SignedUser, Tag, Version};

/// User ID Packet
/// <https://tools.ietf.org/html/rfc4880.html#section-5.11>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    packet_version: Version,
    id: BString,
}

impl UserId {
    /// Parses a `UserId` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        Ok(UserId {
            packet_version,
            id: BString::from(input),
        })
    }

    pub fn from_str(packet_version: Version, input: &str) -> Self {
        UserId {
            packet_version,
            id: BString::from(input),
        }
    }

    pub fn id(&self) -> &BStr {
        self.id.as_ref()
    }

    /// Create a self-signature
    pub fn sign<R, F>(&self, rng: R, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUser>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        self.sign_third_party(rng, key, key_pw, key)
    }

    /// Create a third-party signature
    pub fn sign_third_party<R, F>(
        &self,
        mut rng: R,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
    ) -> Result<SignedUser>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        let hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            Utc::now().trunc_subsecs(0),
        ))];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))];

        let mut config = match signer.version() {
            KeyVersion::V4 => SignatureConfig::v4(
                SignatureType::CertGeneric,
                signer.algorithm(),
                signer.hash_alg(),
            ),
            KeyVersion::V6 => SignatureConfig::v6(
                &mut rng,
                SignatureType::CertGeneric,
                signer.algorithm(),
                signer.hash_alg(),
            )?,
            v => unsupported_err!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = hashed_subpackets;
        config.unhashed_subpackets = unhashed_subpackets;

        let sig =
            config.sign_certification_third_party(signer, signer_pw, signee, self.tag(), &self)?;

        Ok(SignedUser::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUser {
        SignedUser::new(self, vec![sig])
    }
}

impl Serialize for UserId {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.id)?;

        Ok(())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User ID: \"{}\"", self.id)
    }
}

impl PacketTrait for UserId {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::UserId
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::types::KeyVersion;
    use crate::{packet, KeyType};

    #[test]
    fn test_user_id_certification() {
        let key_type = KeyType::EdDSALegacy;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let alice_sec = packet::SecretKey::new(
            packet::PublicKey::new(
                Version::New,
                KeyVersion::V4,
                key_type.to_alg(),
                Utc::now().trunc_subsecs(0),
                None,
                public_params,
            )
            .unwrap(),
            secret_params,
        );

        let alice_pub = alice_sec.public_key();

        let alice_uid = UserId::from_str(Version::New, "<alice@example.org>");

        // test self-signature
        let self_signed = alice_uid
            .sign(&mut rng, &alice_sec, String::default)
            .unwrap();
        self_signed
            .verify(&alice_pub)
            .expect("self signature verification failed");

        // test third-party signature
        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let signer_sec = packet::SecretKey::new(
            packet::PublicKey::new(
                Version::New,
                KeyVersion::V4,
                key_type.to_alg(),
                Utc::now().trunc_subsecs(0),
                None,
                public_params,
            )
            .unwrap(),
            secret_params,
        );

        let signer_pub = signer_sec.public_key();

        let third_signed = alice_uid
            .sign_third_party(&mut rng, &signer_sec, String::default, &alice_pub)
            .unwrap();
        third_signed
            .verify_third_party(&alice_pub, &signer_pub)
            .expect("self signature verification failed");
    }
}
