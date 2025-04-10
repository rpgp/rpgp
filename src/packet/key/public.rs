use std::io::BufRead;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use md5::Md5;
use rand::{CryptoRng, Rng};
use rsa::traits::PublicKeyParts;
use sha1_checked::{Digest, Sha1};

use crate::{
    crypto::{self, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, ensure, ensure_eq, unimplemented_err, unsupported_err, Result},
    packet::{PacketHeader, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::{
        EcdhPublicParams, EddsaLegacyPublicParams, EskType, Fingerprint, KeyDetails, KeyId,
        KeyVersion, Mpi, Password, PkeskBytes, PublicKeyTrait, PublicParams, SecretKeyTrait,
        SignatureBytes, Tag,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    packet_header: PacketHeader,
    inner: PubKeyInner,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicSubkey {
    packet_header: PacketHeader,
    inner: PubKeyInner,
}

impl PublicKey {
    pub fn from_inner(inner: PubKeyInner) -> Result<Self> {
        let len = inner.write_len();
        let packet_header = PacketHeader::new_fixed(Tag::PublicKey, len.try_into()?);
        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub(super) fn from_inner_with_header(packet_header: PacketHeader, inner: PubKeyInner) -> Self {
        Self {
            packet_header,
            inner,
        }
    }

    /// Create a new `PublicKey` packet from underlying parameters.
    pub fn new_with_header(
        packet_header: PacketHeader,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;

        if let Some(len) = packet_header.packet_length().maybe_len() {
            ensure_eq!(
                inner.write_len(),
                len as usize,
                "PublicKey: inconsisteng packet length"
            );
        }
        ensure_eq!(packet_header.tag(), Tag::PublicKey, "invalid tag");

        Ok(Self {
            packet_header,
            inner,
        })
    }

    /// Parses a `PublicKeyKey` packet.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::PublicKey, "invalid tag");

        let inner = PubKeyInner::try_from_reader(input)?;

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn sign<R: CryptoRng + Rng, K>(
        &self,
        rng: R,
        key: &K,
        key_pw: Password,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait + Serialize,
    {
        self.inner.sign(rng, key, key_pw, SignatureType::KeyBinding)
    }

    pub fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.inner, rng, plain, typ)
    }
}

impl PublicSubkey {
    pub fn from_inner(inner: PubKeyInner) -> Result<Self> {
        let len = inner.write_len();
        let packet_header = PacketHeader::new_fixed(Tag::PublicSubkey, len.try_into()?);

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn from_inner_with_header(packet_header: PacketHeader, inner: PubKeyInner) -> Result<Self> {
        Ok(Self {
            packet_header,
            inner,
        })
    }

    /// Create a new `PublicSubkey` packet from underlying parameters.
    pub fn new_with_header(
        packet_header: PacketHeader,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;

        if let Some(len) = packet_header.packet_length().maybe_len() {
            ensure_eq!(
                inner.write_len(),
                len as usize,
                "PublicSubkey: inconsistent packet length"
            );
        }
        ensure_eq!(packet_header.tag(), Tag::PublicSubkey, "invalid tag");
        Ok(Self {
            packet_header,
            inner,
        })
    }

    /// Parses a `PublicSubkey` packet from the given buffer.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::PublicSubkey, "invalid tag");
        let inner = PubKeyInner::try_from_reader(input)?;

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn sign<R: CryptoRng + Rng, K>(
        &self,
        rng: R,
        key: &K,
        key_pw: Password,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait + Serialize,
    {
        self.inner
            .sign(rng, key, key_pw, SignatureType::SubkeyBinding)
    }

    pub fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.inner, rng, plain, typ)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[doc(hidden)] // must leak for proptest to work
pub struct PubKeyInner {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: chrono::DateTime<chrono::Utc>,
    expiration: Option<u16>,
    public_params: PublicParams,
}

impl PubKeyInner {
    fn try_from_reader<B: BufRead>(input: B) -> Result<Self> {
        let details = crate::packet::public_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params) = details;

        Self::new(version, algorithm, created_at, expiration, public_params)
    }

    pub fn new(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: chrono::DateTime<chrono::Utc>,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        // None of the ECC methods described in this document are allowed with deprecated version 3 keys.
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-11-2)
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

        // "Ed25519Legacy and Curve25519Legacy are used only in version 4 keys [..].
        // Implementations MUST NOT accept [..] version 6 key material using the deprecated OIDs."
        //
        // See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.2-6
        if version != KeyVersion::V4 {
            if matches!(
                public_params,
                PublicParams::ECDH(EcdhPublicParams::Curve25519 { .. })
            ) {
                bail!(
                    "ECDH over Curve25519 is illegal for key version {}",
                    u8::from(version)
                );
            }

            if matches!(public_params, PublicParams::EdDSALegacy { .. }) {
                bail!(
                    "EdDSALegacy is illegal for key version {}",
                    u8::from(version)
                );
            }
        }

        Ok(Self {
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        })
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

    fn writer_len_v2_v3(&self) -> usize {
        let mut sum = 4 + 2 + 1;
        sum += self.public_params.write_len();
        sum
    }

    fn to_writer_v4_v6<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        writer.write_u32::<BigEndian>(self.created_at.timestamp().try_into()?)?;
        writer.write_u8(self.algorithm.into())?;

        if self.version == KeyVersion::V6 {
            writer.write_u32::<BigEndian>(self.public_params.write_len().try_into()?)?;
        }

        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn writer_len_v4_v6(&self) -> usize {
        let mut sum = 4 + 1;

        if self.version == KeyVersion::V6 {
            sum += 4;
        }
        sum += self.public_params.write_len();

        sum
    }

    fn sign<R: CryptoRng + Rng, K>(
        &self,
        mut rng: R,
        key: &K,
        key_pw: Password,
        sig_type: SignatureType,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait + Serialize,
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
        ))?];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];

        config.sign_key(key, key_pw, &self)
    }
}

pub(crate) fn encrypt<R: rand::CryptoRng + rand::Rng, K: PublicKeyTrait>(
    key: &K,
    mut rng: R,
    plain: &[u8],
    typ: EskType,
) -> Result<PkeskBytes> {
    match key.public_params() {
        PublicParams::RSA(ref params) => crypto::rsa::encrypt(rng, &params.key, plain),
        PublicParams::EdDSALegacy { .. } => bail!("EdDSALegacy is only used for signing"),
        PublicParams::Ed25519 { .. } => bail!("Ed25519 is only used for signing"),
        PublicParams::Ed448 { .. } => bail!("Ed448 is only used for signing"),
        PublicParams::ECDSA { .. } => bail!("ECDSA is only used for signing"),
        PublicParams::ECDH(ref params) => match params {
            EcdhPublicParams::Unsupported { ref curve, .. } => {
                unsupported_err!("ECDH over curve {:?} is unsupported", curve)
            }
            _ => {
                if key.version() == KeyVersion::V6 {
                    // An implementation MUST NOT encrypt any message to a version 6 ECDH key over a
                    // listed curve that announces a different KDF or KEK parameter.
                    //
                    // (See https://www.rfoc-editor.org/rfc/rfc9580.html#section-11.5.1-2)
                    let curve = params.curve();
                    match params {
                        EcdhPublicParams::Curve25519 { hash, alg_sym, .. }
                        | EcdhPublicParams::P256 { hash, alg_sym, .. }
                        | EcdhPublicParams::P521 { hash, alg_sym, .. }
                        | EcdhPublicParams::P384 { hash, alg_sym, .. } => {
                            if curve.hash_algo()? != *hash || curve.sym_algo()? != *alg_sym {
                                bail!("Unsupported KDF/KEK parameters for {:?} and KeyVersion::V6: {:?}, {:?}", curve, hash, alg_sym);
                            }
                        }
                        _ => unsupported_err!("{:?} for ECDH", params),
                    }
                }

                crypto::ecdh::encrypt(rng, params, key.fingerprint().as_bytes(), plain)
            }
        },
        PublicParams::X25519(ref params) => {
            let (sym_alg, plain) = match typ {
                EskType::V6 => (None, plain),
                EskType::V3_4 => {
                    ensure!(!plain.is_empty(), "plain may not be empty");

                    (
                        Some(plain[0].into()), // byte 0 is the symmetric algorithm
                        &plain[1..],           // strip symmetric algorithm
                    )
                }
            };

            let (ephemeral, session_key) = crypto::x25519::encrypt(&mut rng, &params.key, plain)?;

            Ok(PkeskBytes::X25519 {
                ephemeral,
                session_key: session_key.into(),
                sym_alg,
            })
        }
        PublicParams::X448(ref params) => {
            let (sym_alg, plain) = match typ {
                EskType::V6 => (None, plain),
                EskType::V3_4 => {
                    ensure!(!plain.is_empty(), "plain may not be empty");

                    (
                        Some(plain[0].into()), // byte 0 is the symmetric algorithm
                        &plain[1..],           // strip symmetric algorithm
                    )
                }
            };

            let (ephemeral, session_key) = crypto::x448::encrypt(&mut rng, params, plain)?;

            Ok(PkeskBytes::X448 {
                ephemeral,
                session_key: session_key.into(),
                sym_alg,
            })
        }
        PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
        PublicParams::DSA { .. } => bail!("DSA is only used for signing"),
        PublicParams::Unknown { .. } => bail!("Unknown algorithm"),
    }
}

impl crate::ser::Serialize for PublicKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.inner.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        self.inner.write_len()
    }
}

impl crate::ser::Serialize for PublicSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.inner.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        self.inner.write_len()
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

    fn write_len(&self) -> usize {
        let mut sum = 1;
        sum += match self.version {
            KeyVersion::V2 | KeyVersion::V3 => self.writer_len_v2_v3(),
            KeyVersion::V4 | KeyVersion::V6 => self.writer_len_v4_v6(),
            KeyVersion::V5 => panic!("V5 keys"),
            KeyVersion::Other(v) => {
                panic!("Unsupported key version {}", v)
            }
        };
        sum
    }
}

impl crate::packet::PacketTrait for PublicKey {
    fn packet_header(&self) -> &crate::packet::PacketHeader {
        &self.packet_header
    }
}

impl crate::packet::PacketTrait for PublicSubkey {
    fn packet_header(&self) -> &crate::packet::PacketHeader {
        &self.packet_header
    }
}

impl KeyDetails for PubKeyInner {
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
                h.update([0x9B]);

                // a.2) four-octet scalar octet count of (b)-(f)
                let total_len: u32 = 1 + 4 + 1 + 4 + pp.len() as u32;
                h.write_u32::<BigEndian>(total_len)
                    .expect("write to hasher");

                // b) version number = 6 (1 octet);
                h.update([0x06]);

                // c) timestamp of key creation (4 octets);
                h.write_u32::<BigEndian>(self.created_at.timestamp() as u32)
                    .expect("write to hasher");

                // d) algorithm (1 octet);
                h.update([self.algorithm.into()]);

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
                PublicParams::RSA(params) => {
                    let n: Mpi = params.key.n().into();
                    let offset = n.len() - 8;
                    let raw: [u8; 8] = n.as_ref()[offset..].try_into().expect("fixed size");
                    raw.into()
                }
                _ => panic!("invalid key constructed: {:?}", &self.public_params),
            },
            KeyVersion::V4 => {
                // Lower 64 bits
                let f = self.fingerprint();
                let offset = f.len() - 8;
                let raw: [u8; 8] = f.as_bytes()[offset..].try_into().expect("fixed size");
                raw.into()
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::V6 => {
                // High 64 bits
                let f = self.fingerprint();
                let raw: [u8; 8] = f.as_bytes()[0..8].try_into().expect("fixed size");
                raw.into()
            }
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }
}

impl PublicKeyTrait for PubKeyInner {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        match self.public_params {
            PublicParams::RSA(ref params) => {
                let sig: &[Mpi] = sig.try_into()?;

                ensure_eq!(sig.len(), 1, "invalid signature");
                crypto::rsa::verify(&params.key, hash, hashed, sig[0].as_ref())
            }
            PublicParams::EdDSALegacy(ref params) => {
                match params {
                    EddsaLegacyPublicParams::Ed25519 { ref key } => {
                        let sig: &[Mpi] = sig.try_into()?;

                        ensure_eq!(sig.len(), 2);

                        let r = sig[0].as_ref();
                        let s = sig[1].as_ref();

                        ensure!(r.len() < 33, "invalid R (len)");
                        ensure!(s.len() < 33, "invalid S (len)");

                        let mut sig_bytes = vec![0u8; 64];
                        // add padding if the values were encoded short
                        sig_bytes[(32 - r.len())..32].copy_from_slice(r);
                        sig_bytes[32 + (32 - s.len())..].copy_from_slice(s);

                        crypto::ed25519::verify(key, hash, hashed, &sig_bytes)
                    }
                    EddsaLegacyPublicParams::Unsupported { curve, .. } => {
                        unsupported_err!("curve {:?} for EdDSA", curve.to_string());
                    }
                }
            }
            PublicParams::Ed25519(ref params) => {
                crypto::ed25519::verify(&params.key, hash, hashed, sig.try_into()?)
            }
            PublicParams::Ed448(ref params) => {
                crypto::ed448::verify(&params.key, hash, hashed, sig.try_into()?)
            }
            PublicParams::X25519 { .. } => {
                bail!("X25519 can not be used for verify operations");
            }
            PublicParams::X448 { .. } => {
                bail!("X448 can not be used for verify operations");
            }
            PublicParams::ECDSA(ref params) => {
                let sig: &[Mpi] = sig.try_into()?;

                crypto::ecdsa::verify(params, hash, hashed, sig)
            }
            PublicParams::ECDH(
                ref params @ EcdhPublicParams::Curve25519 { .. }
                | ref params @ EcdhPublicParams::P256 { .. }
                | ref params @ EcdhPublicParams::P384 { .. }
                | ref params @ EcdhPublicParams::P521 { .. },
            ) => {
                bail!("ECDH ({:?}) can not be used for verify operations", params,);
            }
            PublicParams::ECDH(
                EcdhPublicParams::Brainpool256 { .. }
                | EcdhPublicParams::Brainpool384 { .. }
                | EcdhPublicParams::Brainpool512 { .. },
            ) => {
                bail!("ECDH (unsupported: brainpool) can not be used for verify operations");
            }
            PublicParams::ECDH(EcdhPublicParams::Unsupported { ref curve, .. }) => {
                bail!(
                    "ECDH (unsupported: {:?}) can not be used for verify operations",
                    curve,
                );
            }
            PublicParams::Elgamal { .. } => {
                unimplemented_err!("verify Elgamal");
            }
            PublicParams::DSA(ref params) => {
                let sig: &[Mpi] = sig.try_into()?;
                ensure_eq!(sig.len(), 2, "invalid signature");

                crypto::dsa::verify(params, hashed, sig[0].clone().into(), sig[1].clone().into())
            }
            PublicParams::Unknown { .. } => {
                unimplemented_err!("PublicParams::Unknown can not be used for verify operations");
            }
        }
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

impl KeyDetails for PublicKey {
    fn version(&self) -> KeyVersion {
        self.inner.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.inner.algorithm()
    }
}
impl PublicKeyTrait for PublicKey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.inner, hash, hashed, sig)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.inner)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.inner)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.inner)
    }
}

impl KeyDetails for PublicSubkey {
    fn version(&self) -> KeyVersion {
        self.inner.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.inner.algorithm()
    }
}

impl PublicKeyTrait for PublicSubkey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.inner, hash, hashed, sig)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.inner)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.inner)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::packet::PacketTrait;

    fn v3_alg() -> BoxedStrategy<PublicKeyAlgorithm> {
        prop_oneof![Just(PublicKeyAlgorithm::RSA),].boxed()
    }
    fn v4_alg() -> BoxedStrategy<PublicKeyAlgorithm> {
        prop_oneof![
            Just(PublicKeyAlgorithm::RSA),
            Just(PublicKeyAlgorithm::DSA),
            Just(PublicKeyAlgorithm::ECDSA),
            Just(PublicKeyAlgorithm::ECDH),
            Just(PublicKeyAlgorithm::Elgamal),
            Just(PublicKeyAlgorithm::EdDSALegacy),
            Just(PublicKeyAlgorithm::Ed25519),
            Just(PublicKeyAlgorithm::X25519),
        ]
        .boxed()
    }
    fn v6_alg() -> BoxedStrategy<PublicKeyAlgorithm> {
        prop_oneof![
            Just(PublicKeyAlgorithm::RSA),
            Just(PublicKeyAlgorithm::DSA),
            Just(PublicKeyAlgorithm::ECDSA),
            Just(PublicKeyAlgorithm::Elgamal),
            Just(PublicKeyAlgorithm::Ed25519),
            Just(PublicKeyAlgorithm::X25519),
            // cfg is not working here
            // Just(PublicKeyAlgorithm::X448),
        ]
        .boxed()
    }

    impl Arbitrary for PubKeyInner {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<(KeyVersion, u32, u16)>()
                .prop_flat_map(|(version, created_at, expiration)| {
                    let created_at = chrono::Utc
                        .timestamp_opt(created_at as i64, 0)
                        .single()
                        .expect("invalid time");
                    match version {
                        KeyVersion::V2 | KeyVersion::V3 => (
                            Just(version),
                            Just(created_at),
                            Just(Some(expiration)),
                            v3_alg(),
                        ),
                        KeyVersion::V4 => (Just(version), Just(created_at), Just(None), v4_alg()),
                        KeyVersion::V5 | KeyVersion::V6 => {
                            (Just(version), Just(created_at), Just(None), v6_alg())
                        }
                        KeyVersion::Other(_) => unimplemented!(),
                    }
                })
                .prop_flat_map(|(version, created_at, expiration, algorithm)| {
                    (
                        Just(version),
                        Just(algorithm),
                        Just(created_at),
                        Just(expiration),
                        any_with::<PublicParams>(algorithm),
                    )
                })
                .prop_map(|(version, algorithm, created_at, expiration, pub_params)| {
                    PubKeyInner::new(version, algorithm, created_at, expiration, pub_params)
                        .unwrap()
                })
                .boxed()
        }
    }

    impl Arbitrary for PublicKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<PubKeyInner>()
                .prop_map(|k| PublicKey::from_inner(k).unwrap())
                .boxed()
        }
    }

    impl Arbitrary for PublicSubkey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<PubKeyInner>()
                .prop_map(|k| PublicSubkey::from_inner(k).unwrap())
                .boxed()
        }
    }

    proptest! {
        #[test]
        #[ignore]
        fn public_key_write_len(packet: PublicKey) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        #[ignore]
        fn public_key_packet_roundtrip(packet: PublicKey) {
            // dyn compat
            let _: Box<&dyn PublicKeyTrait> = Box::new(&packet);

            let mut buf = Vec::new();
            packet.to_writer(&mut buf)?;
            let new_packet = PublicKey::try_from_reader(*packet.packet_header(), &mut &buf[..])?;
            prop_assert_eq!(packet, new_packet);
        }

        #[test]
        #[ignore]
        fn public_sub_key_write_len(packet: PublicSubkey) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        #[ignore]
        fn public_sub_key_packet_roundtrip(packet: PublicSubkey) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf)?;
            let new_packet = PublicSubkey::try_from_reader(*packet.packet_header(), &mut &buf[..])?;
            prop_assert_eq!(packet, new_packet);
        }
    }
}
