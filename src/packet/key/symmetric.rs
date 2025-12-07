//! Persistent Symmetric Keys in OpenPGP
//!
//! Ref <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/>

use std::{
    fmt::{Debug, Formatter},
    io::BufRead,
};

use bytes::Bytes;
use log::debug;
use rand::{CryptoRng, Rng};

use crate::{
    composed::PlainSessionKey,
    crypto::{
        aead::AeadAlgorithm, aead_key::InfoParameter, hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm, Signer,
    },
    errors::{bail, ensure, ensure_eq, unsupported_err},
    packet::{PacketHeader, PacketTrait, PubKeyInner, SignatureVersion},
    ser::Serialize,
    types::{
        DecryptionKey, EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion,
        Password, PkeskBytes, PlainSecretParams, PublicParams, SecretParams, SignatureBytes,
        SigningKey, Tag, Timestamp, VerifyingKey,
    },
};

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct PersistentSymmetricKey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: super::PublicKey,
    secret_params: SecretParams,
}

impl PersistentSymmetricKey {
    pub fn new(
        details: super::PublicKey,
        secret_params: SecretParams,
    ) -> crate::errors::Result<Self> {
        ensure_eq!(
            details.version(),
            KeyVersion::V6,
            "Illegal version {:?}",
            details.version()
        );

        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::PersistentSymmetricKey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `SecretKey` packet from the given buffer.
    pub fn try_from_reader<B: BufRead>(
        packet_header: PacketHeader,
        input: B,
    ) -> crate::errors::Result<Self> {
        ensure_eq!(
            Tag::PersistentSymmetricKey,
            packet_header.tag(),
            "invalid tag"
        );

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;

        ensure_eq!(version, KeyVersion::V6, "Illegal version {version:?}",);

        ensure_eq!(
            algorithm,
            PublicKeyAlgorithm::AEAD,
            "Only PublicKeyAlgorithm::AEAD is allowed for PersistentSymmetricKey"
        );

        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;
        let len = inner.write_len();

        let pub_packet_header = PacketHeader::from_parts(
            packet_header.version(),
            Tag::PublicKey,
            crate::types::PacketLength::Fixed(len.try_into()?),
        )?;

        let details = super::PublicKey::from_inner_with_header(pub_packet_header, inner);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    pub fn unlock<G, T>(
        &self,
        pw: &Password,
        work: G,
    ) -> crate::errors::Result<crate::errors::Result<T>>
    where
        G: FnOnce(&PublicParams, &PlainSecretParams) -> crate::errors::Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => Ok(work(pub_params, k)),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                Ok(work(pub_params, &plain))
            }
        }
    }

    pub fn public_key(&self) -> &super::PublicKey {
        &self.details
    }

    pub fn as_unlockable<'a>(
        &'a self,
        key_pw: &'a Password,
    ) -> UnlockablePersistentSymmetricKey<'a> {
        UnlockablePersistentSymmetricKey { psk: self, key_pw }
    }
}

pub struct UnlockablePersistentSymmetricKey<'a> {
    psk: &'a PersistentSymmetricKey,
    key_pw: &'a Password,
}

impl EncryptionKey for PersistentSymmetricKey {
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        mut rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes> {
        ensure!(
            matches!(typ, EskType::V6),
            "only v6 ESK supported right now"
        );

        let aead = AeadAlgorithm::Ocb; // FIXME: parameter

        // 32 octets of salt. The salt is used to derive the key-encryption key and MUST be
        // securely generated (see section 13.10 of [RFC9580]).
        let mut salt: [u8; 32] = [0; 32];
        rng.fill(&mut salt);

        let SecretParams::Plain(PlainSecretParams::AEAD(secret)) = &self.secret_params else {
            unimplemented!();
        };

        let PublicParams::AEAD(public_params) = &self.details.public_params() else {
            unimplemented!();
        };

        // A symmetric key encryption of the plaintext value described in section 5.1 of [RFC9580],
        // performed with the key-encryption key and IV computed as described in Section 7.4,
        // using the symmetric-key cipher of the key and the indicated AEAD mode, with as
        // additional data the empty string; including the authentication tag.

        let version = self.details.version().into();
        let info = InfoParameter {
            tag: Tag::PublicKeyEncryptedSessionKey,
            version,
            aead,
            sym_alg: public_params.sym_alg,
        };

        let (key, iv) = crate::crypto::aead_key::SecretKey::derive(&secret.key, &salt, info);

        let mut buf = plain.into();

        aead.encrypt_in_place(&public_params.sym_alg, &key, &iv, &[], &mut buf)?;

        let encrypted: Bytes = buf.into();

        Ok(PkeskBytes::Aead {
            aead,
            salt,
            encrypted,
        })
    }
}

impl SigningKey for PersistentSymmetricKey {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> crate::errors::Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |_pub_params, priv_key| {
            let PlainSecretParams::AEAD(secret) = &priv_key else {
                unsupported_err!(
                    "Unsupported signing algorithm {:?} for a persistent symmetric key",
                    priv_key
                );
            };

            debug!("unlocked key");

            let sig = secret.sign(hash, data)?;
            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl DecryptionKey for PersistentSymmetricKey {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> crate::errors::Result<crate::errors::Result<PlainSessionKey>> {
        self.unlock(key_pw, |pub_params, sec_params| {
            debug!("unlocked key");

            let PlainSecretParams::AEAD(_secret) = &sec_params else {
                unsupported_err!(
                    "Unsupported encryption algorithm {:?} for a persistent symmetric key",
                    sec_params
                );
            };

            Ok(sec_params.decrypt(pub_params, values, typ, &self))
        })?
    }
}

impl<'a> KeyDetails for UnlockablePersistentSymmetricKey<'a> {
    fn version(&self) -> KeyVersion {
        self.psk.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.psk.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.psk.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.psk.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.psk.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.psk.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.psk.public_params()
    }
}

impl<'a> Debug for UnlockablePersistentSymmetricKey<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.psk.fmt(f)
    }
}

impl<'a> VerifyingKey for UnlockablePersistentSymmetricKey<'a> {
    fn verify(
        &self,
        _hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> crate::errors::Result<()> {
        let SignatureBytes::PersistentSymmetric(aead, salt, tag) = sig else {
            unimplemented!();
        };

        ensure_eq!(
            tag.len(),
            aead.tag_size().unwrap_or(0),
            "unexpected tag length"
        );

        // FIXME: handle encrypted secret params
        let SecretParams::Plain(PlainSecretParams::AEAD(secret)) = &self.psk.secret_params else {
            unimplemented!();
        };

        let version = SignatureVersion::V6; // FIXME: should not be fixed

        // "buf" is the newly calculated authentication tag
        let buf = secret.calculate_signature(*aead, version, salt, data)?;

        // check if the stored and calculated authentication tags match
        if buf != tag {
            // no: the signature is invalid!
            bail!("PersistentSymmetricKey signature mismatch");
        }

        Ok(())
    }
}

impl PacketTrait for PersistentSymmetricKey {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

impl KeyDetails for PersistentSymmetricKey {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.details.legacy_key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.details.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.details.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

impl Serialize for PersistentSymmetricKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        // writes version and public part
        Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer, self.version())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let details_len = Serialize::write_len(&self.details);
        let secret_params_len = self.secret_params.write_len(self.version());

        details_len + secret_params_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufReader;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::{
        armor::{BlockType, Dearmor},
        composed::{ArmorOptions, Esk, Message, MessageBuilder},
        crypto::{
            aead::{AeadAlgorithm, ChunkSize},
            aead_key,
            hash::HashAlgorithm,
            public_key::PublicKeyAlgorithm,
            sym::SymmetricKeyAlgorithm,
        },
        packet::{
            key::symmetric::PersistentSymmetricKey, Packet, PacketParser, PubKeyInner, PublicKey,
        },
        ser::Serialize,
        types::{
            AeadPublicParams, DecryptionKey, EskType, KeyVersion, Password, PlainSecretParams,
            PublicParams, SecretParams, Timestamp,
        },
    };

    fn make_psk() -> PersistentSymmetricKey {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

        let pp = PublicParams::AEAD(AeadPublicParams {
            sym_alg: SYM_ALG,
            seed: rng.gen(),
        });

        let inner = PubKeyInner::new(
            KeyVersion::V6,
            PublicKeyAlgorithm::AEAD,
            Timestamp::now(),
            None,
            pp,
        )
        .expect("foo");
        let pk = PublicKey::from_inner(inner).expect("foo");

        let key: [u8; SYM_ALG.key_size()] = rng.gen();

        let plainsecret = SecretParams::Plain(PlainSecretParams::AEAD(aead_key::SecretKey {
            key: key.to_vec().into(),
            sym_alg: SYM_ALG,
        }));

        let psk = PersistentSymmetricKey::new(pk, plainsecret).expect("foo");

        let packet = Packet::from(psk.clone());

        let mut out = Vec::new();
        crate::armor::write(&packet, BlockType::PrivateKey, &mut out, None, false)
            .expect("armor writer");
        eprintln!("{}", String::from_utf8(out).expect("utf8"));

        psk
    }

    #[test]
    fn psk_serialize_parse() {
        let psk = make_psk();

        let p = Packet::from(psk);

        let mut out = Vec::new();
        p.to_writer(&mut out).expect("foo");

        eprintln!("{:02x?}", out);

        let packet = PacketParser::new(&out[..]).next().unwrap().unwrap();

        eprintln!("packet {:#?}", packet);

        let Packet::PersistentSymmetricKey(psk) = packet else {
            panic!("foo");
        };

        let SecretParams::Plain(PlainSecretParams::AEAD(ref secret)) = &psk.secret_params else {
            panic!("foo");
        };

        eprintln!("{:02x?}", secret.key);
    }

    #[test]
    fn psk_encrypt() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        const PLAIN: &[u8] = b"hello world";

        let psk = make_psk();

        let mut builder = MessageBuilder::from_bytes(&[][..], PLAIN.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES128,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder.encrypt_to_key(&mut rng, &psk).expect("encryption");

        let encrypted = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .expect("writing");

        eprintln!("{}", encrypted);

        let (msg, _) = Message::from_armor(encrypted.as_bytes()).expect("parse");

        eprintln!("{:#?}", msg);

        let Message::Encrypted { esk, .. } = &msg else {
            panic!("not encrypted");
        };

        assert_eq!(esk.len(), 1);
        let esk = &esk[0];

        let Esk::PublicKeyEncryptedSessionKey(pkesk) = esk else {
            unimplemented!();
        };

        let sk = psk
            .decrypt(&Password::empty(), pkesk.values().unwrap(), EskType::V6)
            .expect("decryption")
            .expect("decryption");

        let mut dec = msg.decrypt_with_session_key(sk).expect("decryption");

        let decrypted = dec.as_data_vec().expect("decryption");

        assert_eq!(PLAIN, decrypted);
    }

    #[test]
    fn psk_sign_msg() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        const PLAIN: &[u8] = b"hello world";

        let psk = make_psk();

        // let signed = psk.to(&mut rng, ArmorOptions::default()).expect("writing");

        let mut builder = MessageBuilder::from_bytes(&[][..], PLAIN.to_vec());
        builder.sign(&psk, Password::empty(), HashAlgorithm::Sha512);

        let signed = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .expect("writing");

        eprintln!("{signed}");

        let (mut msg, _) = Message::from_armor(signed.as_bytes()).expect("parse");
        let _payload = msg.as_data_vec().expect("read");

        msg.verify(&psk.as_unlockable(&Password::empty()))
            .expect("ok");
    }

    #[test]
    fn psk_verify_msg() {
        const KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

6EwGaSRlrgAAAAAhCWxnN1/mMnykeWe9yzydun1gOggIRKNp8qMi4IoirkfGAPAk
XsGytxnhi5ATBz5XOozNS1ZJTujbK2vhVPZk3E4M
-----END PGP PRIVATE KEY BLOCK-----";
        const MSG: &str = "-----BEGIN PGP MESSAGE-----

xEYGAAoAIGw7mqdn94W1N8DYul+lRnfmpuKBMg37snyIm4+kYGcPMRthAHCPzcH0
ZeNcpwSD1zRKuYkrOt8NlYHzo74FWkkByxFiAAAAAABoZWxsbyB3b3JsZMKJBgAA
CgAAACkiIQYxG2EAcI/NwfRl41ynBIPXNEq5iSs63w2VgfOjvgVaSQUCaSRlrgAA
AADo9CBsO5qnZ/eFtTfA2LpfpUZ35qbigTIN+7J8iJuPpGBnDwJ7j2mu35ArcqUG
QpAiHaqE2GWdapfQFTAq9w2kh1NOzZgzl9VQVYs7XA/CYnhHNt8=
=W5gU
-----END PGP MESSAGE-----";

        let dearmor = Dearmor::new(KEY.as_bytes());
        let mut parser = PacketParser::new(BufReader::new(dearmor));
        let packet = parser.next().unwrap().expect("parse");

        let Packet::PersistentSymmetricKey(psk) = packet else {
            unimplemented!()
        };

        let (mut msg, _) = Message::from_armor(MSG.as_bytes()).expect("parse");
        let _payload = msg.as_data_vec().expect("read");

        msg.verify(&psk.as_unlockable(&Password::empty()))
            .expect("ok");
    }
}
