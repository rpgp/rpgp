use std::{fmt, io, str};

use bstr::{BStr, BString};
use chrono::{SubsecRound, Utc};

use crate::errors::Result;
use crate::packet::{
    PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket, SubpacketData,
};
use crate::ser::Serialize;
use crate::types::{PublicKeyTrait, SecretKeyTrait, SignedUser, Tag, Version};

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
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
    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUser>
    where
        F: FnOnce() -> String,
    {
        self.sign_third_party(key, key_pw, key)
    }

    /// Create a third-party signature
    pub fn sign_third_party<F>(
        &self,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
    ) -> Result<SignedUser>
    where
        F: FnOnce() -> String,
    {
        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::CertGeneric)
            .pub_alg(signer.algorithm())
            .hash_alg(signer.hash_alg())
            .hashed_subpackets(vec![Subpacket::regular(
                SubpacketData::SignatureCreationTime(Utc::now().trunc_subsecs(0)),
            )])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                signer.key_id(),
            ))])
            .build()?;

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

    use super::*;
    use crate::types::{KeyVersion, S2kParams};
    use crate::{packet, KeyType};
    use rand::thread_rng;

    #[test]
    fn test_user_id_certification() {
        let key_type = KeyType::EdDSA;

        let (public_params, secret_params) = key_type
            .generate_with_rng(thread_rng(), None, S2kParams::Unprotected)
            .unwrap();

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
        let self_signed = alice_uid.sign(&alice_sec, String::default).unwrap();
        self_signed
            .verify(&alice_pub)
            .expect("self signature verification failed");

        // test third-party signature
        let (public_params, secret_params) = key_type
            .generate_with_rng(thread_rng(), None, S2kParams::Unprotected)
            .unwrap();

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
            .sign_third_party(&signer_sec, String::default, &alice_pub)
            .unwrap();
        third_signed
            .verify_third_party(&alice_pub, &signer_pub)
            .expect("self signature verification failed");
    }
}
