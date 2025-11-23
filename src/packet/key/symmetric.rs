//! Persistent Symmetric Keys in OpenPGP
//!
//! Ref <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/>

use std::io::BufRead;

use chrono::{DateTime, Utc};

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::ensure_eq,
    packet::{PacketHeader, PacketTrait, PubKeyInner},
    ser::Serialize,
    types::{
        Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PlainSecretParams, PublicKeyTrait,
        PublicParams, SecretParams, SignatureBytes, Tag,
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
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> crate::errors::Result<()> {
        todo!()
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Utc;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::{
        composed::MessageBuilder,
        crypto::{
            aead::{AeadAlgorithm, ChunkSize},
            aead_key,
            public_key::PublicKeyAlgorithm,
            sym::SymmetricKeyAlgorithm,
        },
        packet::{
            key::symmetric::PersistentSymmetricKey, Packet, PacketParser, PubKeyInner, PublicKey,
        },
        ser::Serialize,
        types::{AeadPublicParams, KeyVersion, PlainSecretParams, PublicParams, SecretParams},
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

        let encrypted = builder.to_vec(&mut rng).expect("writing");

        eprintln!("{:02x?}", encrypted);
    }
}
