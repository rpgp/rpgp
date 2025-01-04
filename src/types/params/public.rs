use std::io;

use byteorder::WriteBytesExt;

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

#[cfg(test)]
use crate::crypto::public_key::PublicKeyAlgorithm;

/// Represent the public parameters for the different algorithms.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum PublicParams {
    RSA {
        n: Mpi,
        e: Mpi,
    },
    DSA {
        p: Mpi,
        q: Mpi,
        g: Mpi,
        y: Mpi,
    },
    ECDSA(EcdsaPublicParams),
    ECDH(EcdhPublicParams),
    Elgamal {
        p: Mpi,
        g: Mpi,
        y: Mpi,
    },
    EdDSALegacy {
        curve: ECCCurve,
        q: Mpi,
    },
    Ed25519 {
        public: [u8; 32],
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

#[cfg(test)]
pub fn public_params_gen(
    params: PublicKeyAlgorithm,
) -> proptest::prelude::BoxedStrategy<PublicParams> {
    use proptest::prelude::*;

    match params {
        PublicKeyAlgorithm::RSA => prop::arbitrary::any::<(Mpi, Mpi)>()
            .prop_map(|(n, e)| PublicParams::RSA { n, e })
            .boxed(),
        PublicKeyAlgorithm::DSA => prop::arbitrary::any::<(Mpi, Mpi, Mpi, Mpi)>()
            .prop_map(|(p, q, g, y)| PublicParams::DSA { p, q, g, y })
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
        PublicKeyAlgorithm::EdDSALegacy => prop::arbitrary::any::<(ECCCurve, Mpi)>()
            .prop_map(|(curve, q)| PublicParams::EdDSALegacy { curve, q })
            .boxed(),
        PublicKeyAlgorithm::Ed25519 => prop::arbitrary::any::<[u8; 32]>()
            .prop_map(|public| PublicParams::Ed25519 { public })
            .boxed(),
        PublicKeyAlgorithm::X25519 => prop::arbitrary::any::<[u8; 32]>()
            .prop_map(|public| PublicParams::X25519 { public })
            .boxed(),
        PublicKeyAlgorithm::X448 => prop::arbitrary::any::<[u8; 56]>()
            .prop_map(|public| PublicParams::X448 { public })
            .boxed(),
        _ => {
            unimplemented!()
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdhPublicParams {
    /// ECDH public parameters for a curve that we know uses Mpi representation
    Known {
        curve: ECCCurve,
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// Public parameters for a curve that we don't know about (which might not use Mpi representation).
    Unsupported { curve: ECCCurve, opaque: Vec<u8> },
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdsaPublicParams {
    P256 {
        #[cfg_attr(test, proptest(strategy = "p256_pub_gen()"))]
        key: p256::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "p384_pub_gen()"))]
        key: p384::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "p521_pub_gen()"))]
        key: p521::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    Secp256k1 {
        #[cfg_attr(test, proptest(strategy = "k256_pub_gen()"))]
        key: k256::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    Unsupported {
        curve: ECCCurve,
        p: Mpi,
    },
}

#[cfg(test)]
proptest::prop_compose! {
    fn p256_pub_gen()(seed: u64) -> p256::PublicKey {
        use rand::SeedableRng;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        p256::SecretKey::random(&mut rng).public_key()
    }
}
#[cfg(test)]
proptest::prop_compose! {
    fn p384_pub_gen()(seed: u64) -> p384::PublicKey {
        use rand::SeedableRng;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        p384::SecretKey::random(&mut rng).public_key()
    }
}
#[cfg(test)]
proptest::prop_compose! {
    fn p521_pub_gen()(seed: u64) -> p521::PublicKey {
        use rand::SeedableRng;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        p521::SecretKey::random(&mut rng).public_key()
    }
}
#[cfg(test)]
proptest::prop_compose! {
    fn k256_pub_gen()(seed: u64) -> k256::PublicKey {
        use rand::SeedableRng;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        k256::SecretKey::random(&mut rng).public_key()
    }
}

impl EcdsaPublicParams {
    pub fn try_from_mpi(p: MpiRef<'_>, curve: ECCCurve) -> Result<Self> {
        match curve {
            ECCCurve::P256 => {
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P256 {
                    key: public,
                    p: p.to_owned(),
                })
            }
            ECCCurve::P384 => {
                ensure!(p.len() <= 97, "invalid public key length");
                let mut key = [0u8; 97];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p384::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P384 {
                    key: public,
                    p: p.to_owned(),
                })
            }
            ECCCurve::P521 => {
                ensure!(p.len() <= 133, "invalid public key length");
                let mut key = [0u8; 133];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = p521::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P521 {
                    key: public,
                    p: p.to_owned(),
                })
            }
            ECCCurve::Secp256k1 => {
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_bytes());

                let public = k256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::Secp256k1 {
                    key: public,
                    p: p.to_owned(),
                })
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
            EcdsaPublicParams::P256 { p, .. } => {
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::P384 { p, .. } => {
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::P521 { p, .. } => {
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::Secp256k1 { p, .. } => {
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
            EcdsaPublicParams::P256 { p, .. } => {
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::P384 { p, .. } => {
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::P521 { p, .. } => {
                sum += p.as_ref().write_len();
            }
            EcdsaPublicParams::Secp256k1 { p, .. } => {
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
            PublicParams::RSA { ref n, ref e } => {
                n.to_writer(writer)?;
                e.to_writer(writer)?;
            }
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => {
                p.to_writer(writer)?;
                q.to_writer(writer)?;
                g.to_writer(writer)?;
                y.to_writer(writer)?;
            }
            PublicParams::ECDSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::ECDH(EcdhPublicParams::Known {
                ref curve,
                ref p,
                ref hash,
                ref alg_sym,
            }) => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                p.to_writer(writer)?;

                writer.write_u8(0x03)?; // len of the following fields
                writer.write_u8(0x01)?; // fixed tag
                writer.write_u8((*hash).into())?;
                writer.write_u8((*alg_sym).into())?;
            }
            PublicParams::ECDH(EcdhPublicParams::Unsupported {
                ref curve,
                ref opaque,
            }) => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                writer.write_all(opaque)?;
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
            PublicParams::EdDSALegacy { ref curve, ref q } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                q.to_writer(writer)?;
            }
            PublicParams::Ed25519 { ref public } => {
                writer.write_all(&public[..])?;
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
            PublicParams::RSA { ref n, ref e } => {
                sum += n.write_len();
                sum += e.write_len();
            }
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => {
                sum += p.write_len();
                sum += q.write_len();
                sum += g.write_len();
                sum += y.write_len();
            }
            PublicParams::ECDSA(params) => {
                sum += params.write_len();
            }
            PublicParams::ECDH(EcdhPublicParams::Known {
                ref curve, ref p, ..
            }) => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();

                sum += p.write_len();

                sum += 1 + 1 + 1 + 1;
            }
            PublicParams::ECDH(EcdhPublicParams::Unsupported {
                ref curve,
                ref opaque,
            }) => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();

                sum += opaque.len();
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
            PublicParams::EdDSALegacy { ref curve, ref q } => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();

                sum += q.write_len();
            }
            PublicParams::Ed25519 { ref public } => {
                sum += public.len();
            }
            PublicParams::X25519 { ref public } => {
                sum += public.len();
            }
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
