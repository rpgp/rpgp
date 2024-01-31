use std::{fmt, io};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

/// Represent the public paramaters for the different algorithms.
#[derive(PartialEq, Eq, Clone)]
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
    EdDSA {
        curve: ECCCurve,
        q: Mpi,
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
            EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1.oid(),
            EcdsaPublicParams::Unsupported { curve, .. } => curve.oid(),
        };

        writer.write_all(&[oid.len() as u8])?;
        writer.write_all(&oid)?;

        match self {
            EcdsaPublicParams::P256 { p, .. } => {
                p.as_ref().to_writer(writer)?;
            }
            EcdsaPublicParams::P384 { p, .. } => {
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
                writer.write_all(&[oid.len() as u8])?;
                writer.write_all(&oid)?;

                p.to_writer(writer)?;

                writer.write_all(&[
                    // len of the following fields
                    0x03,
                    // fixed tag
                    0x01,
                    *hash as u8,
                    *alg_sym as u8,
                ])?;
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
            PublicParams::EdDSA { ref curve, ref q } => {
                let oid = curve.oid();
                writer.write_all(&[oid.len() as u8])?;
                writer.write_all(&oid)?;

                q.to_writer(writer)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for PublicParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicParams::RSA { ref n, ref e } => f
                .debug_struct("PublicParams::RSA")
                .field("n", &n)
                .field("e", &e)
                .finish(),
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => f
                .debug_struct("PublicParams::DSA")
                .field("p", &p)
                .field("q", &q)
                .field("g", &y)
                .field("y", &g)
                .finish(),
            PublicParams::ECDSA(params) => {
                write!(f, "PublicParams::ECDSA({params:?})")
            }
            PublicParams::ECDH {
                ref curve,
                ref p,
                hash,
                alg_sym,
            } => f
                .debug_struct("PublicParams::ECDH")
                .field("curve", curve)
                .field("hash", hash)
                .field("alg_sym", alg_sym)
                .field("p", &p)
                .finish(),
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => f
                .debug_struct("PublicParams::Elgamal")
                .field("p", &p)
                .field("g", &g)
                .field("y", &y)
                .finish(),

            PublicParams::EdDSA { ref curve, ref q } => f
                .debug_struct("PublicParams::EdDSA")
                .field("curve", curve)
                .field("q", &q)
                .finish(),
        }
    }
}
