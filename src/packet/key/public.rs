use aes_gcm::aead::rand_core::CryptoRng;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use md5::Md5;
use rand::Rng;
use sha1_checked::{Digest, Sha1};

use crate::types::{EskType, Mpi};
use crate::{
    crypto::{self, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{
        Fingerprint, KeyId, KeyVersion, PublicKeyTrait, PublicParams, SecretKeyTrait,
        SignatureBytes, Tag, Version,
    },
    EskBytes,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey(PubKeyInner);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicSubkey(PubKeyInner);

impl PublicKey {
    /// Create a new `PublicKey` packet from underlying parameters.
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

    pub fn sign<R: CryptoRng + Rng, F>(
        &self,
        rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(rng, key, key_pw, SignatureType::KeyBinding)
    }
}

impl PublicSubkey {
    /// Create a new `PublicSubkey` packet from underlying parameters.
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

    /// Parses a `PublicSubkey` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let inner = PubKeyInner::from_slice(packet_version, input)?;
        Ok(Self(inner))
    }

    pub fn sign<R: CryptoRng + Rng, F>(
        &self,
        rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(rng, key, key_pw, SignatureType::SubkeyBinding)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PubKeyInner {
    packet_version: Version,
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: chrono::DateTime<chrono::Utc>,
    expiration: Option<u16>,
    public_params: PublicParams,
}

impl PubKeyInner {
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

    fn to_writer_v2_v3<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        writer.write_u32::<BigEndian>(self.created_at.timestamp().try_into()?)?;
        writer.write_u16::<BigEndian>(
            self.expiration
                .expect("old key versions have an expiration"),
        )?;
        writer.write_u8(self.algorithm.into())?;
        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn to_writer_v4_v6<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        writer.write_u32::<BigEndian>(self.created_at.timestamp().try_into()?)?;
        writer.write_u8(self.algorithm.into())?;

        let mut public_params = vec![];
        self.public_params.to_writer(&mut public_params)?;

        if self.version == KeyVersion::V6 {
            writer.write_u32::<BigEndian>(public_params.len().try_into()?)?;
        }

        writer.write_all(&public_params)?;

        Ok(())
    }

    fn sign<R: CryptoRng + Rng, F>(
        &self,
        mut rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
        sig_type: SignatureType,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        use chrono::SubsecRound;

        let mut config = match key.version() {
            KeyVersion::V4 => SignatureConfig::v4(sig_type, key.algorithm(), key.hash_alg()),
            KeyVersion::V6 => {
                SignatureConfig::v6(&mut rng, sig_type, key.algorithm(), key.hash_alg())?
            }
            v => unsupported_err!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            chrono::Utc::now().trunc_subsecs(0),
        ))];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))];

        config.sign_key(key, key_pw, &self)
    }
}

impl crate::ser::Serialize for PublicKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }
}

impl crate::ser::Serialize for PublicSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }
}

impl crate::ser::Serialize for PubKeyInner {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version.into())?;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => self.to_writer_v2_v3(writer),
            KeyVersion::V4 | KeyVersion::V6 => self.to_writer_v4_v6(writer),
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

impl crate::packet::PacketTrait for PublicSubkey {
    fn packet_version(&self) -> Version {
        self.0.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::PublicSubkey
    }
}

impl PublicKeyTrait for PubKeyInner {
    fn version(&self) -> KeyVersion {
        self.version
    }

    fn fingerprint(&self) -> Fingerprint {
        use crate::ser::Serialize;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => {
                let mut h = Md5::new();
                self.public_params
                    .to_writer(&mut h)
                    .expect("write to hasher");
                let digest = h.finalize();

                if self.version == KeyVersion::V2 {
                    Fingerprint::V2(digest.into())
                } else {
                    Fingerprint::V3(digest.into())
                }
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

                let digest = h.finalize();

                Fingerprint::V4(digest.into())
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::V6 => {
                // Serialize public parameters
                let mut pp: Vec<u8> = vec![];
                self.public_params
                    .to_writer(&mut pp)
                    .expect("serialize to Vec<u8>");

                // A v6 fingerprint is the 256-bit SHA2-256 hash of:
                let mut h = sha2::Sha256::new();

                // a.1) 0x9B (1 octet)
                h.update(&[0x9B]);

                // a.2) four-octet scalar octet count of (b)-(f)
                let total_len: u32 = 1 + 4 + 1 + 4 + pp.len() as u32;
                h.write_u32::<BigEndian>(total_len)
                    .expect("write to hasher");

                // b) version number = 6 (1 octet);
                h.update(&[0x06]);

                // c) timestamp of key creation (4 octets);
                h.write_u32::<BigEndian>(self.created_at.timestamp() as u32)
                    .expect("write to hasher");

                // d) algorithm (1 octet);
                h.update(&[self.algorithm.into()]);

                // e) four-octet scalar octet count for the following key material;
                h.write_u32::<BigEndian>(pp.len() as u32)
                    .expect("write to hasher");

                // f) algorithm-specific fields.
                h.update(&pp);

                let digest = h.finalize();

                Fingerprint::V6(digest.into())
            }
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

                KeyId::from_slice(&f.as_bytes()[offset..]).expect("fixed size slice")
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::V6 => {
                // High 64 bits
                let f = self.fingerprint();

                KeyId::from_slice(&f.as_bytes()[0..8]).expect("fixed size slice")
            }
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        match self.public_params {
            PublicParams::RSA { ref n, ref e } => {
                let sig: &[Mpi] = sig.try_into()?;

                ensure_eq!(sig.len(), 1, "invalid signature");
                crypto::rsa::verify(n.as_bytes(), e.as_bytes(), hash, hashed, sig[0].as_bytes())
            }
            PublicParams::EdDSALegacy { ref curve, ref q } => {
                let sig: &[Mpi] = sig.try_into()?;

                ensure_eq!(sig.len(), 2);

                let r = sig[0].as_bytes();
                let s = sig[1].as_bytes();

                ensure!(r.len() < 33, "invalid R (len)");
                ensure!(s.len() < 33, "invalid S (len)");
                ensure_eq!(q.len(), 33, "invalid Q (len)");
                ensure_eq!(q[0], 0x40, "invalid Q (prefix)");

                let public = &q[1..];

                let mut sig_bytes = vec![0u8; 64];
                // add padding if the values were encoded short
                sig_bytes[(32 - r.len())..32].copy_from_slice(r);
                sig_bytes[32 + (32 - s.len())..].copy_from_slice(s);

                crypto::eddsa::verify(curve, public, hash, hashed, &sig_bytes)
            }
            PublicParams::Ed25519 { ref public } => crypto::eddsa::verify(
                &crypto::ecc_curve::ECCCurve::Ed25519,
                public,
                hash,
                hashed,
                sig.try_into()?,
            ),
            PublicParams::X25519 { .. } => {
                unimplemented_err!("verify X25519");
            }
            PublicParams::X448 { .. } => {
                unimplemented_err!("verify X448");
            }
            PublicParams::ECDSA(ref params) => {
                let sig: &[Mpi] = sig.try_into()?;

                crypto::ecdsa::verify(params, hash, hashed, sig)
            }
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
                let sig: &[Mpi] = sig.try_into()?;

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
        mut rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<EskBytes> {
        match self.public_params {
            PublicParams::RSA { ref n, ref e } => {
                crypto::rsa::encrypt(rng, n.as_bytes(), e.as_bytes(), plain)
            }
            PublicParams::EdDSALegacy { .. } => bail!("EdDSALegacy is only used for signing"),
            PublicParams::Ed25519 { .. } => bail!("Ed25519 is only used for signing"),
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
                self.fingerprint().as_bytes(),
                p.as_bytes(),
                plain,
            ),
            PublicParams::X25519 { ref public } => {
                match typ {
                    EskType::V6 => {
                        let (ephemeral, session_key) =
                            crypto::x25519::encrypt(&mut rng, *public, plain)?;

                        Ok(EskBytes::X25519 {
                            ephemeral,
                            session_key,
                            sym_alg: None,
                        })
                    }
                    EskType::V3_4 => {
                        // v3 pkesk / v4 skesk

                        // byte 0 is the symmetric algo, in v3 pkesk
                        let sym_alg = Some(plain[0].into());
                        // for v3: strip algorithm
                        let plain = &plain[1..];

                        let (ephemeral, session_key) =
                            crypto::x25519::encrypt(&mut rng, *public, plain)?;

                        Ok(EskBytes::X25519 {
                            ephemeral,
                            session_key,
                            sym_alg,
                        })
                    }
                }
            }
            PublicParams::X448 { ref public } => {
                match typ {
                    EskType::V6 => {
                        let (ephemeral, session_key) =
                            crypto::x448::encrypt(&mut rng, *public, plain)?;

                        Ok(EskBytes::X448 {
                            ephemeral,
                            session_key,
                            sym_alg: None,
                        })
                    }
                    EskType::V3_4 => {
                        // v3 pkesk / v4 skesk

                        // byte 0 is the symmetric algo, in v3 pkesk
                        let sym_alg = Some(plain[0].into());
                        // for v3: strip algorithm
                        let plain = &plain[1..];

                        let (ephemeral, session_key) =
                            crypto::x448::encrypt(&mut rng, *public, plain)?;

                        Ok(EskBytes::X448 {
                            ephemeral,
                            session_key,
                            sym_alg,
                        })
                    }
                }
            }
            PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
            PublicParams::DSA { .. } => bail!("DSA is only used for signing"),
            PublicParams::Unknown { .. } => bail!("Unknown algorithm"),
        }
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        use crate::ser::Serialize;

        let mut key_buf = Vec::new();
        self.to_writer(&mut key_buf)?;

        // old style packet header for the key
        match self.version() {
            KeyVersion::V2 | KeyVersion::V3 | KeyVersion::V4 => {
                // When a v4 signature is made over a key, the hash data starts with the octet 0x99,
                // followed by a two-octet length of the key, and then the body of the key packet.
                writer.write_u8(0x99)?;
                writer.write_u16::<BigEndian>(key_buf.len().try_into()?)?;
            }

            KeyVersion::V6 => {
                // When a v6 signature is made over a key, the hash data starts with the salt
                // [NOTE: the salt is hashed in packet/signature/config.rs],

                // then octet 0x9B, followed by a four-octet length of the key,
                // and then the body of the key packet.
                writer.write_u8(0x9b)?;
                writer.write_u32::<BigEndian>(key_buf.len().try_into()?)?;
            }

            v => unimplemented_err!("key version {:?}", v),
        }

        writer.write_all(&key_buf)?;

        Ok(())
    }

    fn public_params(&self) -> &PublicParams {
        &self.public_params
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.created_at
    }

    fn expiration(&self) -> Option<u16> {
        self.expiration
    }
}

impl PublicKeyTrait for PublicKey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<EskBytes> {
        PublicKeyTrait::encrypt(&self.0, rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::serialize_for_hashing(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }

    fn version(&self) -> KeyVersion {
        PublicKeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Fingerprint {
        PublicKeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        PublicKeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyTrait::algorithm(&self.0)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.0)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.0)
    }
}

impl PublicKeyTrait for PublicSubkey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<EskBytes> {
        PublicKeyTrait::encrypt(&self.0, rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::serialize_for_hashing(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }

    fn version(&self) -> KeyVersion {
        PublicKeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Fingerprint {
        PublicKeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        PublicKeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyTrait::algorithm(&self.0)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.0)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.0)
    }
}
