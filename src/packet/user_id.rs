use std::{io, io::BufRead, str};

use bytes::Bytes;
use chrono::{SubsecRound, Utc};
use rand::{CryptoRng, RngCore};

use crate::{
    errors::{ensure, Result},
    packet::{
        PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData, CERTIFICATION_SIGNATURE_TYPES,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        KeyVersion, PacketHeaderVersion, PacketLength, Password, PublicKeyTrait, SecretKeyTrait,
        SignedUser, Tag,
    },
};

/// User ID Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13>
///
/// # Examples
///
/// The following example lists [`UserId`]s in a certificate ("public key"):
///
/// ```
/// # fn main() -> testresult::TestResult {
/// use pgp::composed::{Deserializable, SignedPublicKey};
///
/// let file = std::fs::File::open("tests/carol.pub.asc")?;
/// let (spk, _armor_header) = SignedPublicKey::from_reader_single(file)?;
/// let users = spk.details.users;
///
/// assert_eq!(users.len(), 1);
/// assert_eq!(users[0].id.id(), b"Carol Oldstyle <carol@openpgp.example>");
/// # Ok(()) }
/// ```
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
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let id = input.rest()?;
        Ok(UserId {
            packet_header,
            id: id.freeze(),
        })
    }

    /// Creates a `UserId` from the given string.
    pub fn from_str(packet_version: PacketHeaderVersion, input: impl AsRef<str>) -> Result<Self> {
        let id: Bytes = input.as_ref().as_bytes().to_vec().into();

        let len = PacketLength::Fixed(id.len().try_into()?);
        let packet_header = PacketHeader::from_parts(packet_version, Tag::UserId, len)?;

        Ok(UserId { packet_header, id })
    }

    /// Returns the actual id.
    ///
    /// Should be valid UTF-8, but not guaranteed, to be more compatible with existing data.
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    #[inline]
    /// Extracts the raw ID.
    pub fn into_bytes(self) -> Bytes {
        self.id
    }

    #[inline]
    /// Tries to convert the ID as a UTF-8 string, returning raw bytes as Err if not
    /// valid UTF-8 string.
    pub fn try_into_string(self) -> Result<String, Bytes> {
        let Self { id, .. } = self;
        match std::string::String::from_utf8(Vec::from(id)) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into_bytes().into()),
        }
    }

    /// Tries to convert the ID as a UTF-8 string.
    /// Returns `None` if the data is not valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.id).ok()
    }

    /// Create a self-signature.
    pub fn sign<R, K, P>(
        &self,
        rng: &mut R,
        signer_sec_key: &K,
        signer_pub_key: &P,
        key_pw: &Password,
    ) -> Result<SignedUser>
    where
        R: CryptoRng + RngCore + ?Sized,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        // Self-signatures use CertPositive, see
        // <https://www.ietf.org/archive/id/draft-gallagher-openpgp-signatures-01.html#name-certification-signature-typ>
        self.sign_third_party(
            rng,
            signer_sec_key,
            key_pw,
            signer_pub_key,
            SignatureType::CertPositive,
        )
    }

    /// Create a third-party signature.
    pub fn sign_third_party<R, P, K>(
        &self,
        rng: &mut R,
        signer: &P,
        signer_pw: &Password,
        signee: &K,
        typ: SignatureType,
    ) -> Result<SignedUser>
    where
        R: CryptoRng + RngCore + ?Sized,
        P: SecretKeyTrait,
        K: PublicKeyTrait + Serialize,
    {
        ensure!(
            CERTIFICATION_SIGNATURE_TYPES.contains(&typ),
            "typ must be a certifying signature type"
        );

        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                Utc::now().trunc_subsecs(0),
            ))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
        ];

        let mut config = SignatureConfig::from_key(rng, signer, typ)?;

        config.hashed_subpackets = hashed_subpackets;
        if signer.version() <= KeyVersion::V4 {
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))?];
        }

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
    use crate::{
        composed::KeyType,
        packet,
        types::{KeyVersion, PacketHeaderVersion},
    };

    prop_compose! {
        pub fn id_gen()(id in "[a-zA-Z]+") -> Bytes {
            Bytes::from(id)
        }
    }

    #[test]
    fn test_user_id_certification() {
        let key_type = KeyType::Ed25519Legacy;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let pub_key = packet::PubKeyInner::new(
            KeyVersion::V4,
            key_type.to_alg(),
            Utc::now().trunc_subsecs(0),
            None,
            public_params,
        )
        .unwrap();
        let pub_key = packet::PublicKey::from_inner(pub_key).unwrap();
        let alice_sec = packet::SecretKey::new(pub_key, secret_params).unwrap();

        let alice_pub = alice_sec.public_key();

        let alice_uid = UserId::from_str(PacketHeaderVersion::New, "<alice@example.org>").unwrap();

        // test self-signature
        let self_signed = alice_uid
            .sign(&mut rng, &alice_sec, &alice_pub, &"".into())
            .unwrap();
        self_signed
            .verify(&alice_pub)
            .expect("self signature verification failed");

        // test third-party signature
        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let pub_key = packet::PubKeyInner::new(
            KeyVersion::V4,
            key_type.to_alg(),
            Utc::now().trunc_subsecs(0),
            None,
            public_params,
        )
        .unwrap();
        let pub_key = packet::PublicKey::from_inner(pub_key).unwrap();
        let signer_sec = packet::SecretKey::new(pub_key, secret_params).unwrap();

        let signer_pub = signer_sec.public_key();

        let third_signed = alice_uid
            .sign_third_party(
                &mut rng,
                &signer_sec,
                &"".into(),
                &alice_pub,
                SignatureType::CertGeneric,
            )
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
            let new_user_id = UserId::try_from_reader(user_id.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(user_id, new_user_id);
        }
    }
}
