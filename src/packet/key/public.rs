use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use md5::Md5;
use sha1_checked::{Digest, Sha1};

use crate::{
    crypto::{self, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{Signature, SignatureConfigBuilder, SignatureType, Subpacket, SubpacketData},
    types::{
        KeyId, KeyTrait, KeyVersion, Mpi, PublicKeyTrait, PublicParams, SecretKeyTrait, Tag,
        Version,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct PubKeyInner {
    pub(crate) packet_version: Version,
    pub(crate) version: KeyVersion,
    pub(crate) algorithm: PublicKeyAlgorithm,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) expiration: Option<u16>,
    pub(crate) public_params: PublicParams,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey(PubKeyInner);

impl PubKeyInner {
    /// Create a new `PublicKeyKey` packet from underlying parameters.
    fn new(
        packet_version: Version,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        if (version == KeyVersion::V2 || version == KeyVersion::V3)
            && !(algorithm == PublicKeyAlgorithm::RSA
                || algorithm == PublicKeyAlgorithm::RSAEncrypt
                || algorithm == PublicKeyAlgorithm::RSASign)
        {
            // It's sufficient to throw a "soft" Error::Unsupported
            unsupported_err!(
                "Invalid algorithm {:?} for key version: {:?}",
                algorithm,
                version,
            );
        }

        Ok(Self {
            packet_version,
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        })
    }

    /// Parses a `PublicKeyKey` packet from the given slice.
    fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, details) = crate::packet::public_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params) = details;

        Self::new(
            packet_version,
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        )
    }

    fn to_writer_old<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
        writer.write_u16::<BigEndian>(
            self.expiration
                .expect("old key versions have an expiration"),
        )?;
        writer.write_all(&[self.algorithm.into()])?;
        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn to_writer_new<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
        writer.write_all(&[self.algorithm.into()])?;
        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn sign<F>(
        &self,
        key: &impl SecretKeyTrait,
        key_pw: F,
        sig_type: SignatureType,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        use chrono::SubsecRound;

        let mut config = SignatureConfigBuilder::default();
        config
            .typ(sig_type)
            .pub_alg(key.algorithm())
            .hash_alg(key.hash_alg())
            .hashed_subpackets(vec![Subpacket::regular(
                SubpacketData::SignatureCreationTime(chrono::Utc::now().trunc_subsecs(0)),
            )])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                key.key_id(),
            ))])
            .build()?
            .sign_key(key, key_pw, &self)
    }
}

impl crate::ser::Serialize for PublicKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer(writer)
    }
}

impl crate::ser::Serialize for PubKeyInner {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[u8::from(self.version)])?;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => self.to_writer_old(writer),
            KeyVersion::V4 => self.to_writer_new(writer),
            KeyVersion::V5 => unimplemented_err!("V5 keys"),
            KeyVersion::Other(v) => {
                unimplemented_err!("Unsupported key version {}", v)
            }
        }
    }
}

impl crate::packet::PacketTrait for PublicKey {
    fn packet_version(&self) -> Version {
        self.0.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::PublicKey
    }
}

impl KeyTrait for PublicKey {
    /// Returns the fingerprint of this key.
    ///
    /// In case of SHA1 collisions, the "mitigated" hash digest is returned.
    fn fingerprint(&self) -> Vec<u8> {
        self.0.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.0.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm
    }
}

impl KeyTrait for PubKeyInner {
    /// Returns the fingerprint of this key.
    ///
    /// In case of SHA1 collisions, the "mitigated" hash digest is returned.
    fn fingerprint(&self) -> Vec<u8> {
        use crate::ser::Serialize;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => {
                let mut h = Md5::new();
                self.public_params
                    .to_writer(&mut h)
                    .expect("write to hasher");
                h.finalize().to_vec()
            }
            KeyVersion::V4 => {
                // A one-octet version number (4).
                let mut packet = vec![4, 0, 0, 0, 0];

                // A four-octet number denoting the time that the key was created.
                BigEndian::write_u32(&mut packet[1..5], self.created_at.timestamp() as u32);

                // A one-octet number denoting the public-key algorithm of this key.
                packet.push(self.algorithm.into());
                self.public_params
                    .to_writer(&mut packet)
                    .expect("write to vec");

                let mut h = Sha1::new();
                h.update([0x99]);
                h.write_u16::<BigEndian>(packet.len() as u16)
                    .expect("write to hasher");
                h.update(&packet);

                h.finalize().to_vec()
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn key_id(&self) -> KeyId {
        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
                PublicParams::RSA { n, .. } => {
                    let offset = n.len() - 8;

                    KeyId::from_slice(&n.as_bytes()[offset..]).expect("fixed size slice")
                }
                _ => panic!("invalid key constructed: {:?}", &self.public_params),
            },
            KeyVersion::V4 => {
                // Lower 64 bits
                let f = self.fingerprint();
                let offset = f.len() - 8;

                KeyId::from_slice(&f[offset..]).expect("fixed size slice")
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }
}

impl PublicKeyTrait for PubKeyInner {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        match self.public_params {
            PublicParams::RSA { ref n, ref e } => {
                ensure_eq!(sig.len(), 1, "invalid signature");
                crypto::rsa::verify(n.as_bytes(), e.as_bytes(), hash, hashed, sig[0].as_bytes())
            }
            PublicParams::EdDSA { ref curve, ref q } => {
                crypto::eddsa::verify(curve, q.as_bytes(), hash, hashed, sig)
            }
            PublicParams::ECDSA(ref params) => crypto::ecdsa::verify(params, hash, hashed, sig),
            PublicParams::ECDH {
                ref curve,
                ref hash,
                ref alg_sym,
                ..
            } => {
                unimplemented_err!("verify ECDH: {:?} {:?} {:?}", curve, hash, alg_sym);
            }
            PublicParams::Elgamal { .. } => {
                unimplemented_err!("verify Elgamal");
            }
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => {
                ensure_eq!(sig.len(), 2, "invalid signature");

                crypto::dsa::verify(
                    p.into(),
                    q.into(),
                    g.into(),
                    y.into(),
                    hashed,
                    sig[0].clone().into(),
                    sig[1].clone().into(),
                )
            }
            PublicParams::Unknown { .. } => {
                unimplemented_err!("verify unknown");
            }
        }
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        let res = match self.public_params {
            PublicParams::RSA { ref n, ref e } => {
                crypto::rsa::encrypt(rng, n.as_bytes(), e.as_bytes(), plain)
            }
            PublicParams::EdDSA { .. } => bail!("EdDSA is only used for signing"),
            PublicParams::ECDSA { .. } => bail!("ECDSA is only used for signing"),
            PublicParams::ECDH {
                ref curve,
                hash,
                alg_sym,
                ref p,
            } => crypto::ecdh::encrypt(
                rng,
                curve,
                alg_sym,
                hash,
                &self.fingerprint(),
                p.as_bytes(),
                plain,
            ),
            PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
            PublicParams::DSA { .. } => bail!("DSA is only used for signing"),
            PublicParams::Unknown { .. } => bail!("Unknown algorithm"),
        }?;

        Ok(res
            .iter()
            .map(|v| Mpi::from_raw_slice(&v[..]))
            .collect::<Vec<_>>())
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        use crate::ser::Serialize;

        let mut key_buf = Vec::new();
        self.to_writer(&mut key_buf)?;

        // old style packet header for the key
        writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
        writer.write_all(&key_buf)?;

        Ok(())
    }
}

impl PublicKeyTrait for PublicKey {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        self.0.verify_signature(hash, hashed, sig)
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        self.0.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::to_writer_old(&self.0, writer)
    }
}

impl PublicKey {
    /// Create a new `PublicKeyKey` packet from underlying parameters.
    pub fn new(
        packet_version: Version,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(
            packet_version,
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        )?;
        Ok(Self(inner))
    }

    /// Parses a `PublicKeyKey` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let inner = PubKeyInner::from_slice(packet_version, input)?;
        Ok(Self(inner))
    }

    pub fn version(&self) -> KeyVersion {
        self.0.version
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm
    }

    pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.0.created_at
    }

    pub fn expiration(&self) -> Option<u16> {
        self.0.expiration
    }

    pub fn public_params(&self) -> &PublicParams {
        &self.0.public_params
    }

    pub(super) fn to_writer_old<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer_old(writer)
    }

    pub(super) fn to_writer_new<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer_new(writer)
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(key, key_pw, SignatureType::KeyBinding)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicSubkey(PubKeyInner);

impl PublicSubkey {
    /// Create a new `PublicKeyKey` packet from underlying parameters.
    pub fn new(
        packet_version: Version,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(
            packet_version,
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        )?;
        Ok(Self(inner))
    }

    /// Parses a `PublicKeyKey` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let inner = PubKeyInner::from_slice(packet_version, input)?;
        Ok(Self(inner))
    }

    pub fn version(&self) -> KeyVersion {
        self.0.version
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm
    }

    pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.0.created_at
    }

    pub fn expiration(&self) -> Option<u16> {
        self.0.expiration
    }

    pub fn public_params(&self) -> &PublicParams {
        &self.0.public_params
    }

    pub(super) fn to_writer_old<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer_old(writer)
    }

    pub(super) fn to_writer_new<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer_new(writer)
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(key, key_pw, SignatureType::SubkeyBinding)
    }
}

impl crate::ser::Serialize for PublicSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.0.to_writer(writer)
    }
}

impl crate::packet::PacketTrait for PublicSubkey {
    fn packet_version(&self) -> Version {
        self.0.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::PublicSubkey
    }
}

impl KeyTrait for PublicSubkey {
    /// Returns the fingerprint of this key.
    ///
    /// In case of SHA1 collisions, the "mitigated" hash digest is returned.
    fn fingerprint(&self) -> Vec<u8> {
        self.0.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.0.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm()
    }
}

impl PublicKeyTrait for PublicSubkey {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        self.0.verify_signature(hash, hashed, sig)
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        self.0.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::to_writer_old(&self.0, writer)
    }
}
