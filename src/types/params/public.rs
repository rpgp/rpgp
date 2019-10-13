use std::{fmt, io};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::Mpi;

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
    ECDSA {
        curve: ECCCurve,
        p: Mpi,
    },
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
            PublicParams::ECDSA { ref curve, ref p } => {
                let oid = curve.oid();
                writer.write_all(&[oid.len() as u8])?;
                writer.write_all(&oid)?;

                p.to_writer(writer)?;
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
            PublicParams::ECDSA { ref curve, ref p } => f
                .debug_struct("PublicParams::ECDSA")
                .field("curve", curve)
                .field("p", &p)
                .finish(),
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
                .field("g", &y)
                .field("y", &g)
                .finish(),

            PublicParams::EdDSA { ref curve, ref q } => f
                .debug_struct("PublicParams::EdDSA")
                .field("curve", curve)
                .field("q", &q)
                .finish(),
        }
    }
}
