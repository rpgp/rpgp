use std::io;

use byteorder::WriteBytesExt;
use dsa::BigUint;
use elliptic_curve::sec1::ToEncodedPoint;
use rsa::traits::PublicKeyParts;

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

#[cfg(test)]
pub use tests::public_params_gen;

/// Represent the public parameters for the different algorithms.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum PublicParams {
    RSA(RsaPublicParams),
    DSA(DsaPublicParams),
    ECDSA(EcdsaPublicParams),
    ECDH(EcdhPublicParams),
    Elgamal {
        p: Mpi,
        g: Mpi,
        y: Mpi,
    },
    EdDSALegacy(EddsaLegacyPublicParams),
    Ed25519 {
        public: ed25519_dalek::VerifyingKey,
    },
    X25519 {
        public: [u8; 32],
    },
    #[cfg(feature = "unstable-curve448")]
    X448 {
        public: [u8; 56],
    },
    Unknown {
        data: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::dsa_pub_gen()"))]
    pub key: dsa::VerifyingKey,
}

impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    pub fn try_from_mpi(
        p: MpiRef<'_>,
        q: MpiRef<'_>,
        g: MpiRef<'_>,
        y: MpiRef<'_>,
    ) -> Result<Self> {
        let components = dsa::Components::from_components(p.into(), q.into(), g.into())?;
        let key = dsa::VerifyingKey::from_components(components, y.into())?;

        Ok(DsaPublicParams { key })
    }
}

impl Serialize for DsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let c = self.key.components();
        let p: Mpi = c.p().into();
        p.to_writer(writer)?;
        let q: Mpi = c.q().into();
        q.to_writer(writer)?;
        let g: Mpi = c.g().into();
        g.to_writer(writer)?;
        let y: Mpi = self.key.y().into();
        y.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;

        let c = self.key.components();
        let p: Mpi = c.p().into();
        sum += p.write_len();
        let q: Mpi = c.q().into();
        sum += q.write_len();
        let g: Mpi = c.g().into();
        sum += g.write_len();
        let y: Mpi = self.key.y().into();
        sum += y.write_len();
        sum
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct RsaPublicParams {
    #[cfg_attr(test, proptest(strategy = "tests::rsa_pub_gen()"))]
    pub key: rsa::RsaPublicKey,
}

impl RsaPublicParams {
    pub fn try_from_mpi(n: MpiRef<'_>, e: MpiRef<'_>) -> Result<Self> {
        let key = rsa::RsaPublicKey::new_with_max_size(
            BigUint::from_bytes_be(n.as_bytes()),
            BigUint::from_bytes_be(e.as_bytes()),
            crate::crypto::rsa::MAX_KEY_SIZE,
        )?;

        Ok(RsaPublicParams { key })
    }
}

impl From<rsa::RsaPublicKey> for RsaPublicParams {
    fn from(key: rsa::RsaPublicKey) -> Self {
        RsaPublicParams { key }
    }
}
impl Serialize for RsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let n: Mpi = self.key.n().into();
        let e: Mpi = self.key.e().into();

        n.to_writer(writer)?;
        e.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let n: Mpi = self.key.n().into();
        let e: Mpi = self.key.e().into();

        let mut sum = n.write_len();
        sum += e.write_len();
        sum
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EddsaLegacyPublicParams {
    Ed25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ed25519_pub_gen()"))]
        key: ed25519_dalek::VerifyingKey,
    },
    #[cfg_attr(test, proptest(skip))]
    Unsupported { curve: ECCCurve, mpi: Mpi },
}

impl EddsaLegacyPublicParams {
    pub fn try_from_mpi(curve: ECCCurve, mpi: MpiRef<'_>) -> Result<Self> {
        match curve {
            ECCCurve::Ed25519 => {
                ensure_eq!(mpi.len(), 33, "invalid Q (len)");
                ensure_eq!(mpi[0], 0x40, "invalid Q (prefix)");
                let public = &mpi[1..];

                let key: ed25519_dalek::VerifyingKey = public.try_into()?;
                Ok(Self::Ed25519 { key })
            }
            _ => Ok(Self::Unsupported {
                curve,
                mpi: mpi.to_owned(),
            }),
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Ed25519 { .. } => ECCCurve::Ed25519,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }
}

impl Serialize for EddsaLegacyPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                mpi.to_writer(writer)?;
            }
            Self::Unsupported { curve, mpi } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                mpi.to_writer(writer)?;
            }
        }
        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519.oid();
                sum += 1;
                sum += oid.len();

                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::Unsupported { curve, mpi } => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();
                sum += mpi.write_len();
            }
        }
        sum
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdhPublicParams {
    /// ECDH public parameters for a curve that we know uses Mpi representation
    Curve25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_curve25519_gen()"))]
        p: x25519_dalek::PublicKey,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P256 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p256_gen()"))]
        p: elliptic_curve::PublicKey<p256::NistP256>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p384_gen()"))]
        p: elliptic_curve::PublicKey<p384::NistP384>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p521_gen()"))]
        p: elliptic_curve::PublicKey<p521::NistP521>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// Public parameters for a curve that we don't know about (which might not use Mpi representation).
    #[cfg_attr(test, proptest(skip))]
    Unsupported { curve: ECCCurve, opaque: Vec<u8> },
}

impl Serialize for EcdhPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = self.curve().oid();
        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        let tags = match self {
            Self::Curve25519 { p, hash, alg_sym } => {
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                mpi.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P256 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P384 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P521 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::Unsupported { opaque, .. } => {
                writer.write_all(&opaque)?;
                None
            }
        };

        if let Some((hash, alg_sym)) = tags {
            writer.write_u8(0x03)?; // len of the following fields
            writer.write_u8(0x01)?; // fixed tag

            writer.write_u8((*hash).into())?;
            writer.write_u8((*alg_sym).into())?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1; // oid len

        match self {
            Self::Curve25519 { p, .. } => {
                sum += self.curve().oid().len();
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::P256 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P384 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P521 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Unsupported { curve, opaque, .. } => {
                let oid = curve.oid();
                sum += oid.len();
                sum += opaque.len();
            }
        };

        if !matches!(self, Self::Unsupported { .. }) {
            // fields and tags
            sum += 1 + 1 + 1 + 1;
        }
        sum
    }
}

impl EcdhPublicParams {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519 { .. } => ECCCurve::Curve25519,
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    pub fn try_from_mpi(
        p: MpiRef<'_>,
        curve: ECCCurve,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    ) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519 => {
                ensure_eq!(p.len(), 33, "invalid public key length");
                // public part of the ephemeral key (removes 0x40 prefix)
                let public_key = &p[1..];

                // create montgomery point
                let mut public_key_arr = [0u8; 32];
                public_key_arr[..].copy_from_slice(public_key);

                let p = x25519_dalek::PublicKey::from(public_key_arr);
                Ok(EcdhPublicParams::Curve25519 { p, hash, alg_sym })
            }
            ECCCurve::P256 => {
                let p = p256::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P256 { p, hash, alg_sym })
            }
            ECCCurve::P384 => {
                let p = p384::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P384 { p, hash, alg_sym })
            }
            ECCCurve::P521 => {
                let p = p521::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P521 { p, hash, alg_sym })
            }
            _ => bail!("unexpected ecdh curve: {:?}", curve),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdsaPublicParams {
    P256 {
        #[cfg_attr(test, proptest(strategy = "tests::p256_pub_gen()"))]
        key: p256::PublicKey,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "tests::p384_pub_gen()"))]
        key: p384::PublicKey,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "tests::p521_pub_gen()"))]
        key: p521::PublicKey,
    },
    Secp256k1 {
        #[cfg_attr(test, proptest(strategy = "tests::k256_pub_gen()"))]
        key: k256::PublicKey,
    },
    #[cfg_attr(test, proptest(skip))]
    Unsupported { curve: ECCCurve, p: Mpi },
}

impl EcdsaPublicParams {
    pub fn try_from_mpi(p: MpiRef<'_>, curve: ECCCurve) -> Result<Self> {
        match curve {
            ECCCurve::P256 => {
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P256 { key: public })
            }
            ECCCurve::P384 => {
                ensure!(p.len() <= 97, "invalid public key length");
                let mut key = [0u8; 97];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p384::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P384 { key: public })
            }
            ECCCurve::P521 => {
                ensure!(p.len() <= 133, "invalid public key length");
                let mut key = [0u8; 133];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p521::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P521 { key: public })
            }
            ECCCurve::Secp256k1 => {
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = k256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::Secp256k1 { key: public })
            }
            _ => Ok(EcdsaPublicParams::Unsupported {
                curve,
                p: p.to_owned(),
            }),
        }
    }

    pub const fn secret_key_length(&self) -> Option<usize> {
        match self {
            EcdsaPublicParams::P256 { .. } => Some(32),
            EcdsaPublicParams::P384 { .. } => Some(48),
            EcdsaPublicParams::P521 { .. } => Some(66),
            EcdsaPublicParams::Secp256k1 { .. } => Some(32),
            EcdsaPublicParams::Unsupported { .. } => None,
        }
    }
}

impl Serialize for EcdsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = match self {
            EcdsaPublicParams::P256 { .. } => ECCCurve::P256.oid(),
            EcdsaPublicParams::P384 { .. } => ECCCurve::P384.oid(),
            EcdsaPublicParams::P521 { .. } => ECCCurve::P521.oid(),
            EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1.oid(),
            EcdsaPublicParams::Unsupported { curve, .. } => curve.oid(),
        };

        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        match self {
            EcdsaPublicParams::P256 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::P384 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::P521 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::Secp256k1 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::Unsupported { p, .. } => {
                p.as_ref().to_writer(writer)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let oid = match self {
            EcdsaPublicParams::P256 { .. } => ECCCurve::P256.oid(),
            EcdsaPublicParams::P384 { .. } => ECCCurve::P384.oid(),
            EcdsaPublicParams::P521 { .. } => ECCCurve::P521.oid(),
            EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1.oid(),
            EcdsaPublicParams::Unsupported { curve, .. } => curve.oid(),
        };

        let mut sum = 1;
        sum += oid.len();

        match self {
            EcdsaPublicParams::P256 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::P384 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::P521 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::Secp256k1 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::Unsupported { p, .. } => {
                sum += p.as_ref().write_len();
            }
        }
        sum
    }
}

impl Serialize for PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicParams::RSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::DSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::ECDSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::ECDH(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => {
                p.to_writer(writer)?;
                g.to_writer(writer)?;
                y.to_writer(writer)?;
            }
            PublicParams::EdDSALegacy(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Ed25519 { ref public } => {
                writer.write_all(&public.as_bytes()[..])?;
            }
            PublicParams::X25519 { ref public } => {
                writer.write_all(&public[..])?;
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448 { ref public } => {
                writer.write_all(&public[..])?;
            }
            PublicParams::Unknown { ref data } => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            PublicParams::RSA(params) => {
                sum += params.write_len();
            }
            PublicParams::DSA(params) => {
                sum += params.write_len();
            }
            PublicParams::ECDSA(params) => {
                sum += params.write_len();
            }
            PublicParams::ECDH(params) => {
                sum += params.write_len();
            }
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => {
                sum += p.write_len();
                sum += g.write_len();
                sum += y.write_len();
            }
            PublicParams::EdDSALegacy(params) => {
                sum += params.write_len();
            }
            PublicParams::Ed25519 { ref public } => {
                sum += public.as_bytes().len();
            }
            PublicParams::X25519 { ref public } => {
                sum += public.len();
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448 { ref public } => {
                sum += public.len();
            }
            PublicParams::Unknown { ref data } => {
                sum += data.len();
            }
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use rand::SeedableRng;

    use crate::crypto::public_key::PublicKeyAlgorithm;

    proptest! {
        #[test]
        fn ecdh_params_write_len(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }
    }

    proptest::prop_compose! {
        pub fn rsa_pub_gen()(seed: u64) -> rsa::RsaPublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap().to_public_key()
        }
    }

    proptest::prop_compose! {
        pub fn dsa_pub_gen()(seed: u64) -> dsa::VerifyingKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let components = dsa::Components::generate(&mut rng, dsa::KeySize::DSA_2048_256);
            let signing_key = dsa::SigningKey::generate(&mut rng, components);
            signing_key.verifying_key().clone()
        }
    }

    proptest::prop_compose! {
        pub fn ed25519_pub_gen()(bytes: [u8; 32]) -> ed25519_dalek::VerifyingKey {
            let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
            ed25519_dalek::VerifyingKey::from(&secret)
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_curve25519_gen()(seed: u64) -> x25519_dalek::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let mut secret_key_bytes = [0u8; ECCCurve::Curve25519.secret_key_length()];
            rng.fill_bytes(&mut secret_key_bytes);

            let secret = x25519_dalek::StaticSecret::from(secret_key_bytes);
            x25519_dalek::PublicKey::from(&secret)
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p256_gen()(seed: u64) -> elliptic_curve::PublicKey<p256::NistP256> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p384_gen()(seed: u64) -> elliptic_curve::PublicKey<p384::NistP384> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p521_gen()(seed: u64) -> elliptic_curve::PublicKey<p521::NistP521> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn p256_pub_gen()(seed: u64) -> p256::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            p256::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn p384_pub_gen()(seed: u64) -> p384::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            p384::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn p521_pub_gen()(seed: u64) -> p521::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            p521::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn k256_pub_gen()(seed: u64) -> k256::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            k256::SecretKey::random(&mut rng).public_key()
        }
    }

    pub fn supported_ecdh_ecc_curve() -> impl Strategy<Value = ECCCurve> {
        prop_oneof![
            Just(ECCCurve::Curve25519),
            Just(ECCCurve::Ed25519),
            Just(ECCCurve::P256),
            Just(ECCCurve::P384),
            Just(ECCCurve::P521),
        ]
    }

    pub fn public_params_gen(
        params: PublicKeyAlgorithm,
    ) -> proptest::prelude::BoxedStrategy<PublicParams> {
        match params {
            PublicKeyAlgorithm::RSA => prop::arbitrary::any::<RsaPublicParams>()
                .prop_map(PublicParams::RSA)
                .boxed(),
            PublicKeyAlgorithm::DSA => prop::arbitrary::any::<DsaPublicParams>()
                .prop_map(PublicParams::DSA)
                .boxed(),
            PublicKeyAlgorithm::ECDSA => prop::arbitrary::any::<EcdsaPublicParams>()
                .prop_map(PublicParams::ECDSA)
                .boxed(),
            PublicKeyAlgorithm::ECDH => prop::arbitrary::any::<EcdhPublicParams>()
                .prop_map(PublicParams::ECDH)
                .boxed(),
            PublicKeyAlgorithm::Elgamal => prop::arbitrary::any::<(Mpi, Mpi, Mpi)>()
                .boxed()
                .prop_map(|(p, g, y)| PublicParams::Elgamal { p, g, y })
                .boxed(),
            PublicKeyAlgorithm::EdDSALegacy => prop::arbitrary::any::<EddsaLegacyPublicParams>()
                .prop_map(PublicParams::EdDSALegacy)
                .boxed(),
            PublicKeyAlgorithm::Ed25519 => ed25519_pub_gen()
                .prop_map(|public| PublicParams::Ed25519 { public })
                .boxed(),
            PublicKeyAlgorithm::X25519 => prop::arbitrary::any::<[u8; 32]>()
                .prop_map(|public| PublicParams::X25519 { public })
                .boxed(),
            #[cfg(feature = "unstable-curve448")]
            PublicKeyAlgorithm::X448 => prop::arbitrary::any::<[u8; 56]>()
                .prop_map(|public| PublicParams::X448 { public })
                .boxed(),
            _ => {
                unimplemented!("{:?}", params)
            }
        }
    }
}
