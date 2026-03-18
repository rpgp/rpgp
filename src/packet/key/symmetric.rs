#![cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys")]

//! Persistent Symmetric Keys in OpenPGP
//!
//! Ref <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html>

use std::{fmt::Debug, io::BufRead};

use log::debug;
use rand::thread_rng;

use crate::{
    composed::PlainSessionKey,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, ensure_eq, unsupported_err},
    packet::{PacketHeader, PacketTrait, PubKeyInner, SignatureVersion},
    ser::Serialize,
    types::{
        DecryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes,
        PlainSecretParams, PublicParams, SecretParams, SignatureBytes, SigningKey, Tag, Timestamp,
    },
};

/// A persistent symmetric key as specified in
/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html>
#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct PersistentSymmetricKey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    pub(crate) details: super::PublicKey,
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

        let len = Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::PersistentSymmetricKey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `PersistentSymmetricKey` packet from the given buffer.
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
            Tag::PersistentSymmetricKey,
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
        // TODO: AEAD encryption (S2K usage octet 253) MUST be used [..]
        // Implementations MUST NOT decrypt symmetric key material in a Persistent Symmetric
        // Key Packet that was encrypted using a different method.

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

    /// Remove the password protection of the private key material in this key packet.
    /// This permanently "unlocks" the secret key material.
    ///
    /// If the Secret Key material in the packet is not locked, it is left unchanged.
    ///
    /// The current locking password for this key must be provided in `password`.
    pub fn remove_password(&mut self, password: &Password) -> crate::errors::Result<()> {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    /// Set a `password` that "locks" the private key material in this key packet
    /// using the mechanisms specified in `s2k_params`.
    ///
    /// To change the password on a locked key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password_with_s2k(
        &mut self,
        password: &Password,
        s2k_params: crate::types::S2kParams,
    ) -> crate::errors::Result<()> {
        // TODO:
        //
        // When storing encrypted symmetric key material in a Persistent Symmetric Key Packet,
        // AEAD encryption (S2K usage octet 253, see section 3.7.2.1 of [RFC9580]) MUST be used,
        // to ensure that the secret key material is bound to the fingerprint.

        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password.read(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
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
        self.unlock(key_pw, |pub_params, priv_key| {
            let PublicParams::AEAD(public) = &pub_params else {
                bail!("Unsupported public parameters for persistent symmetric key: {pub_params:?}");
            };
            let PlainSecretParams::AEAD(secret) = &priv_key else {
                unsupported_err!(
                    "Unsupported signing algorithm {:?} for a persistent symmetric key",
                    priv_key
                );
            };

            debug!("unlocked key");

            let version = match self.version() {
                KeyVersion::V6 => SignatureVersion::V6, // Version 6 keys MUST produce Version 6 signatures

                _ => bail!("Unsupported key version for persistent symmetric key signing"),
            };

            // This trait interface doesn't allow exposing the full flexibility of persistent symmetric
            // key signatures, so we're using fixed values for `rng` and `aead` here.

            // TODO: expose signing with full flexibility as a separate fn on this type?

            let rng = thread_rng();
            let aead = AeadAlgorithm::Ocb;

            let sig = secret.compute_and_wrap_persistent_mac(
                rng,
                version,
                public.sym_alg,
                aead,
                hash,
                data,
            )?;
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

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.details.legacy_v3_expiration_days()
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
        composed::{
            ArmorOptions, Esk, Message, MessageBuilder, TransferablePersistentSymmetricKey,
        },
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
            fingerprint_seed: rng.gen(),
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

        let psk = TransferablePersistentSymmetricKey { key: make_psk() };

        let mut builder = MessageBuilder::from_bytes(&[][..], PLAIN.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES128,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder
            .encrypt_to_key(&mut rng, &psk.to_unlockable(&Password::empty()))
            .expect("encryption");

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
            .key
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

        let tpsk = TransferablePersistentSymmetricKey { key: make_psk() };

        // let signed = psk.to(&mut rng, ArmorOptions::default()).expect("writing");

        let mut builder = MessageBuilder::from_bytes(&[][..], PLAIN.to_vec());
        builder.sign(&tpsk.key, Password::empty(), HashAlgorithm::Sha512);

        let signed = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .expect("writing");

        eprintln!("{signed}");

        let (mut msg, _) = Message::from_armor(signed.as_bytes()).expect("parse");
        let _payload = msg.as_data_vec().expect("read");

        msg.verify(&tpsk.to_unlockable(&Password::empty()))
            .expect("ok");
    }

    #[test]
    fn psk_verify_msg() {
        const KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

6EwGaSRlrgAAAAAhCWxnN1/mMnykeWe9yzydun1gOggIRKNp8qMi4IoirkfGAPAk
XsGytxnhi5ATBz5XOozNS1ZJTujbK2vhVPZk3E4M
-----END PGP PRIVATE KEY BLOCK-----";
        const MSG: &str = "-----BEGIN PGP MESSAGE-----

xEYGAAoAIGw7mqdn94W1N8DYul+lRnfmpuKBMg37snyIm4+kYGcP35p9qQfgQ6s6
2dxCQgmGXX6VFr5+7UlbvUX/4fago8oByxFiAAAAAABoZWxsbyB3b3JsZMKJBgAA
CgAAACkiIQbfmn2pB+BDqzrZ3EJCCYZdfpUWvn7tSVu9Rf/h9qCjygUCaaxTqwAA
AACLjSBsO5qnZ/eFtTfA2LpfpUZ35qbigTIN+7J8iJuPpGBnDwL/UZyh7SdmSF0n
EN6rcnCdGrHtbnaevXgEt/h+4qr8EKogUsV/JxmVOt6NUAF8jKM=
=owYj
-----END PGP MESSAGE-----";

        let dearmor = Dearmor::new(KEY.as_bytes());
        let mut parser = PacketParser::new(BufReader::new(dearmor));
        let packet = parser.next().unwrap().expect("parse");

        let Packet::PersistentSymmetricKey(psk) = packet else {
            unimplemented!()
        };

        let tpsk = TransferablePersistentSymmetricKey { key: psk };

        let (mut msg, _) = Message::from_armor(MSG.as_bytes()).expect("parse");
        let _payload = msg.as_data_vec().expect("read");

        msg.verify(&tpsk.to_unlockable(&Password::empty()))
            .expect("ok");
    }
}
