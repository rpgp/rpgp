use std::{io, str};

use bytes::{Buf, Bytes};
use chrono::{SubsecRound, Utc};
use rand::{CryptoRng, Rng};

use crate::errors::Result;
use crate::packet::{
    PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use crate::ser::Serialize;
use crate::types::{
    KeyVersion, PacketHeaderVersion, PacketLength, PublicKeyTrait, SecretKeyTrait, SignedUser, Tag,
};

/// User ID Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13>
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[display("User ID: \"{:?}\"", id)]
pub struct UserId {
    packet_header: PacketHeader,
    #[cfg_attr(test, proptest(strategy = "tests::id_gen()"))]
    id: Bytes,
}

impl UserId {
    /// Parses a `UserId` packet from the given buffer.
    pub fn from_buf(packet_header: PacketHeader, mut input: impl Buf) -> Result<Self> {
        let len = input.remaining();
        let id = input.copy_to_bytes(len);
        Ok(UserId { packet_header, id })
    }

    /// Creates a `UserId` from the given string.
    pub fn from_str(packet_version: PacketHeaderVersion, input: impl AsRef<str>) -> Result<Self> {
        let id: Bytes = input.as_ref().as_bytes().to_vec().into();

        let len = PacketLength::Fixed(id.len());
        let packet_header = PacketHeader::from_parts(packet_version, Tag::UserId, len)?;

        Ok(UserId { packet_header, id })
    }

    /// Returns the actual id.
    ///
    /// Should be valid UTF-8, but not guaranteed, to be more compatible with existing data.
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
        ))?];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))?];

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
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::types::PacketHeaderVersion;
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
            packet::PubKeyInner::new(
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

        let alice_uid = UserId::from_str(PacketHeaderVersion::New, "<alice@example.org>").unwrap();

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
            packet::PubKeyInner::new(
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
            let new_user_id = UserId::from_buf(user_id.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(user_id, new_user_id);
        }
    }
}
