//! Persistent Symmetric Keys in OpenPGP
//!
//! Ref <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/>

use std::io::BufRead;

use aead::rand_core::CryptoRng;
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use log::debug;
use rand::{thread_rng, Rng};
use sha2::Sha256;

use crate::{
    crypto::{
        aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm, Signer,
    },
    errors::{bail, ensure, ensure_eq, unsupported_err},
    packet::{PacketHeader, PacketTrait, PubKeyInner},
    ser::Serialize,
    types::{
        EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes,
        PlainSecretParams, PublicKeyTrait, PublicParams, SecretKeyTrait, SecretParams,
        SignatureBytes, Tag,
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

    fn calculate_signature(
        &self,
        aead: AeadAlgorithm,
        salt: &[u8; 32],
        digest: &[u8],
    ) -> crate::errors::Result<BytesMut> {
        let SecretParams::Plain(PlainSecretParams::AEAD(plain)) = &self.secret_params else {
            unimplemented!();
        };

        let PublicParams::AEAD(public_params) = &self.details.public_params() else {
            unimplemented!();
        };

        // use key version as signature version (must currently be 6)
        let version = self.details.version().into();

        let info = (Tag::Signature, version, aead, public_params.sym_alg);

        let (key, iv) = derive(&plain.key, salt, info);

        // (&self, sym_algorithm: &SymmetricKeyAlgorithm, key: &[u8], nonce: &[u8], associated_data: &[u8], buffer: &mut BytesMut)
        let mut buf = BytesMut::with_capacity(64);

        // An authentication tag of the size specified by the AEAD mode, created by encrypting the
        // empty value with the message authentication key and IV computed as described in Section
        // 7.4, using the symmetric-key cipher of the key and the indicated AEAD mode, with as
        // additional data the hash digest described in section 5.2.4 of [RFC9580].

        aead.encrypt_in_place(&public_params.sym_alg, &key, &iv, digest, &mut buf)?;

        Ok(buf)
    }
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
        let info = (Tag::Signature, version, aead, public_params.sym_alg);

        let (key, iv) = derive(&secret.key, &salt, info);

        let mut buf = BytesMut::with_capacity(64);

        aead.encrypt_in_place(&public_params.sym_alg, &key, &iv, plain, &mut buf)?;

        let encrypted = buf.into();

        Ok(PkeskBytes::Aead {
            aead,
            salt,
            encrypted,
        })
    }
}

impl Signer for PersistentSymmetricKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> crate::errors::Result<SignatureBytes> {
        // FIXME: should be a parameter?
        let mut rng = thread_rng();

        let Some(digest_size) = hash.digest_size() else {
            bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
        };
        ensure_eq!(
            digest.len(),
            digest_size,
            "Unexpected digest length {} for hash algorithm {:?}",
            digest.len(),
            hash,
        );

        // The signature consists of this series of values:
        //
        // A 1-octet AEAD algorithm (see section 9.6 of [RFC9580]).
        let aead = AeadAlgorithm::Ocb; // FIXME: should be a parameter

        // 32 octets of salt.
        // The salt is used to derive the message authentication key and MUST be securely generated
        // (see section 13.10 of [RFC9580]).
        let mut salt: [u8; 32] = [0; 32];
        rng.fill(&mut salt);

        let buf = self.calculate_signature(aead, &salt, digest)?;

        let mut bytes = Vec::new();
        bytes.push(aead.into());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&buf);

        // TODO: use a separate `SignatureBytes::PSK` variant?
        Ok(SignatureBytes::Native(bytes.into()))
    }
}

impl SecretKeyTrait for PersistentSymmetricKey {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> crate::errors::Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            use crate::crypto::Signer;

            debug!("unlocked key");
            let sig = match *priv_key {
                PlainSecretParams::AEAD(ref priv_key) => self.sign(hash, data)?,

                _ => {
                    unsupported_err!(
                        "Unsupported signing algorithm {:?} for a persistent symmetric key",
                        priv_key
                    );
                }
            };

            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl PublicKeyTrait for PersistentSymmetricKey {
    fn created_at(&self) -> &DateTime<Utc> {
        self.details.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.details.expiration()
    }

    fn verify_signature(
        &self,
        _hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> crate::errors::Result<()> {
        let SignatureBytes::Native(bytes) = sig else {
            unimplemented!();
        };

        let (aead, rest) = bytes.split_at(1);
        let (salt, tag) = rest.split_at(32);

        // "tag" is the stored authentication tag from the signature packet

        ensure_eq!(aead.len(), 1, "couldn't find aead byte");
        let aead: AeadAlgorithm = aead[0].into();

        ensure_eq!(salt.len(), 32, "unexpected salt length");
        ensure_eq!(
            tag.len(),
            aead.tag_size().unwrap_or(0),
            "unexpected tag length"
        );

        // "buf" is the newly calculated authentication tag
        let buf = self.calculate_signature(aead, salt.try_into().expect("32"), data)?;

        // check if the stored and calculated authentication tags match
        if buf != tag {
            // no: the signature is invalid!
            bail!("PersistentSymmetricKey signature mismatch");
        }

        Ok(())
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
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

    fn key_id(&self) -> KeyId {
        self.details.key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
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

/// Key and IV derivation
/// <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-key-and-iv-derivation>
///
/// Returns:
/// - M bits of key, matching the size of SymmetricKeyAlgorithm,
/// - N bit of IV, matching the nonce size of AeadAlgorithm
fn derive(
    persistent_key: &[u8],
    salt: &[u8; 32],
    info: (Tag, u8, AeadAlgorithm, SymmetricKeyAlgorithm),
) -> (Vec<u8>, Vec<u8>) {
    let (tag, version, aead, sym_alg) = info;
    let info_bytes: [u8; 4] = [tag.encode(), version, aead.into(), sym_alg.into()];

    let hk = Hkdf::<Sha256>::new(Some(salt), persistent_key);

    // M + N bits are derived using HKDF.
    // The left-most M bits are used as symmetric algorithm key, the remaining N bits are
    // used as initialization vector.

    // FIXME: zeroize
    let mut output = vec![0u8; sym_alg.key_size() + aead.nonce_size()];
    hk.expand(&info_bytes, &mut output)
        .expect("expand size is < 255 * HashLength");

    let key = output[0..sym_alg.key_size()].to_vec();
    let iv = output[sym_alg.key_size()..].to_vec();

    (key, iv)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufReader;

    use chrono::Utc;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::{
        armor::{BlockType, Dearmor},
        composed::{ArmorOptions, Message, MessageBuilder},
        crypto::{
            aead::{AeadAlgorithm, ChunkSize},
            aead_key,
            hash::HashAlgorithm,
            public_key::PublicKeyAlgorithm,
            sym::SymmetricKeyAlgorithm,
        },
        packet::{
            key::symmetric::{derive, PersistentSymmetricKey},
            Packet, PacketParser, PubKeyInner, PublicKey,
        },
        ser::Serialize,
        types::{
            AeadPublicParams, KeyVersion, Password, PlainSecretParams, PublicParams, SecretParams,
            Tag,
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
            Utc::now(),
            None,
            pp,
        )
        .expect("foo");
        let pk = PublicKey::from_inner(inner).expect("foo");

        let key: [u8; SYM_ALG.key_size()] = rng.gen();

        let plainsecret = SecretParams::Plain(PlainSecretParams::AEAD(aead_key::SecretKey {
            key: key.to_vec(),
        }));

        PersistentSymmetricKey::new(pk, plainsecret).expect("foo")
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
    }

    #[test]
    fn psk_sign_msg() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        const PLAIN: &[u8] = b"hello world";

        let psk = make_psk();

        let packet = Packet::from(psk.clone());

        let mut out = Vec::new();
        crate::armor::write(&packet, BlockType::PrivateKey, &mut out, None, false)
            .expect("armor writer");
        eprintln!("{}", String::from_utf8(out).expect("utf8"));

        // let signed = psk.to(&mut rng, ArmorOptions::default()).expect("writing");

        let mut builder = MessageBuilder::from_bytes(&[][..], PLAIN.to_vec());
        builder.sign(&psk, Password::empty(), HashAlgorithm::Sha512);

        let signed = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .expect("writing");

        eprintln!("{signed}");

        let (mut msg, _) = Message::from_armor(signed.as_bytes()).expect("parse");
        let _payload = msg.as_data_vec().expect("read");

        msg.verify(&psk).expect("ok");
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

        msg.verify(&psk).expect("ok");
    }

    /// Key/IV derivation
    ///
    /// - persistent key: 16 bytes of 0x00
    /// - salt: 32 bytes of 0xff
    /// - info: Signature, Version 6, OCB, AES128
    ///
    /// output:
    /// - key: [e9, de, 26, 72, 2c, fb, 71, 2b, bf, 01, 15, a6, 06, 08, 08, b0]
    /// - iv: [dc, 1f, 35, cc, 3c, 28, 74, 0f, f4, 37, 09, 9e, ad, c0, 17]
    #[test]
    fn psk_derive() {
        let (key, iv) = derive(
            &[0; 16],
            &[0xff; 32],
            (
                Tag::Signature,
                6,
                AeadAlgorithm::Ocb,
                SymmetricKeyAlgorithm::AES128,
            ),
        );

        assert_eq!(
            &key,
            &[
                0xe9, 0xde, 0x26, 0x72, 0x2c, 0xfb, 0x71, 0x2b, 0xbf, 0x01, 0x15, 0xa6, 0x06, 0x08,
                0x08, 0xb0
            ]
        );
        assert_eq!(
            &iv,
            &[
                0xdc, 0x1f, 0x35, 0xcc, 0x3c, 0x28, 0x74, 0x0f, 0xf4, 0x37, 0x09, 0x9e, 0xad, 0xc0,
                0x17
            ]
        );
    }
}
