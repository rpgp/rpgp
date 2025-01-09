use std::{io, str};

use bytes::{Buf, Bytes};
use chrono::{SubsecRound, Utc};
use rand::{CryptoRng, Rng};

use crate::errors::Result;
use crate::packet::{
    PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use crate::ser::Serialize;
use crate::types::{KeyVersion, PublicKeyTrait, SecretKeyTrait, SignedUser, Tag, Version};

/// User ID Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13>
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[display("User ID: \"{:?}\"", id)]
pub struct UserId {
    packet_version: Version,
    #[cfg_attr(test, proptest(strategy = "tests::id_gen()"))]
    id: Bytes,
}

impl UserId {
    /// Parses a `UserId` packet from the given buffer.
    pub fn from_buf(packet_version: Version, mut input: impl Buf) -> Result<Self> {
        let len = input.remaining();
        let id = input.copy_to_bytes(len);
        Ok(UserId { packet_version, id })
    }

    /// Creates a `UserId` from the given string.
    pub fn from_str(packet_version: Version, input: impl AsRef<str>) -> Self {
        UserId {
            packet_version,
            id: input.as_ref().as_bytes().to_vec().into(),
        }
    }

    /// Returns the actual id.
    ///
    /// Should be valid UTF-8, but not guranteed, to be more compatible with existing data.
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// Create a self-signature.
    pub fn sign<R, F>(&self, rng: R, key: &impl SecretKeyTrait, key_pw: F) -> Result<SignedUser>
    where
        R: CryptoRng + Rng,
        F: FnOnce() -> String,
    {
        self.sign_third_party(rng, key, key_pw, key)
    }

    /// Create a third-party signature.
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

    fn write_len(&self) -> usize {
        self.id.len()
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
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::{packet, types::KeyVersion, KeyType};

    prop_compose! {
        pub fn id_gen()(id in "[a-zA-Z]+") -> Bytes {
            Bytes::from(id)
        }
    }

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

    proptest! {
        #[test]
        fn write_len(user_id: UserId) {
            let mut buf = Vec::new();
            user_id.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), user_id.write_len());
        }


        #[test]
        fn packet_roundtrip(user_id: UserId) {
            let mut buf = Vec::new();
            user_id.to_writer(&mut buf).unwrap();
            let new_user_id = UserId::from_buf(user_id.packet_version, &mut &buf[..]).unwrap();
            prop_assert_eq!(user_id, new_user_id);
        }
    }
}
