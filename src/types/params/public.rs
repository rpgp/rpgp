use std::io;

use byteorder::WriteBytesExt;

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

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
    ECDH {
        curve: ECCCurve,
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
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
    X448 {
        public: [u8; 56],
    },
    Unknown {
        data: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EcdsaPublicParams {
    P256 {
        key: p256::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    P384 {
        key: p384::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    P521 {
        key: p521::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    Secp256k1 {
        key: k256::PublicKey,
        /// Stores the original Mpi, to ensure we keep the padding around.
        p: Mpi,
    },
    Unsupported {
        curve: ECCCurve,
        p: Mpi,
    },
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
            PublicParams::ECDH {
                ref curve,
                ref p,
                ref hash,
                ref alg_sym,
            } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                p.to_writer(writer)?;

                writer.write_u8(0x03)?; // len of the following fields
                writer.write_u8(0x01)?; // fixed tag
                writer.write_u8((*hash).into())?;
                writer.write_u8((*alg_sym).into())?;
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
            PublicParams::X448 { ref public } => {
                writer.write_all(&public[..])?;
            }
            PublicParams::Unknown { ref data } => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }
}
