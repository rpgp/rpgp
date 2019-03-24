use std::{fmt, io};

use crypto::ecc_curve::ECCCurve;
use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use ser::Serialize;
use util::write_mpi;

/// Represent the public paramaters for the different algorithms.
#[derive(PartialEq, Eq, Clone)]
pub enum PublicParams {
    RSA {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    DSA {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    ECDSA {
        curve: ECCCurve,
        p: Vec<u8>,
    },
    ECDH {
        curve: ECCCurve,
        p: Vec<u8>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    Elgamal {
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    EdDSA {
        curve: ECCCurve,
        q: Vec<u8>,
    },
}

impl Serialize for PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicParams::RSA { ref n, ref e } => {
                write_mpi(n, writer)?;
                write_mpi(e, writer)?;
            }
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => {
                write_mpi(p, writer)?;
                write_mpi(q, writer)?;
                write_mpi(g, writer)?;
                write_mpi(y, writer)?;
            }
            PublicParams::ECDSA { ref curve, ref p } => {
                let oid = curve.oid();
                writer.write_all(&[oid.len() as u8])?;
                writer.write_all(&oid)?;

                write_mpi(p, writer)?;
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

                write_mpi(p, writer)?;

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
                write_mpi(p, writer)?;
                write_mpi(g, writer)?;
                write_mpi(y, writer)?;
            }
            PublicParams::EdDSA { ref curve, ref q } => {
                let oid = curve.oid();
                writer.write_all(&[oid.len() as u8])?;
                writer.write_all(&oid)?;

                write_mpi(q, writer)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for PublicParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicParams::RSA { ref n, ref e } => f
                .debug_struct("PublicParams::RSA")
                .field("n", &hex::encode(&n))
                .field("e", &hex::encode(&e))
                .finish(),
            PublicParams::DSA {
                ref p,
                ref q,
                ref g,
                ref y,
            } => f
                .debug_struct("PublicParams::DSA")
                .field("p", &hex::encode(&p))
                .field("q", &hex::encode(&q))
                .field("g", &hex::encode(&y))
                .field("y", &hex::encode(&g))
                .finish(),
            PublicParams::ECDSA { ref curve, ref p } => f
                .debug_struct("PublicParams::ECDSA")
                .field("curve", curve)
                .field("p", &hex::encode(p))
                .finish(),
            PublicParams::ECDH {
                ref curve,
                ref p,
                hash,
                alg_sym,
            } => f
                .debug_struct("PublicParams::ECDSA")
                .field("curve", curve)
                .field("hash", hash)
                .field("alg_sym", alg_sym)
                .field("p", &hex::encode(p))
                .finish(),
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => f
                .debug_struct("PublicParams::Elgamal")
                .field("p", &hex::encode(&p))
                .field("g", &hex::encode(&y))
                .field("y", &hex::encode(&g))
                .finish(),

            PublicParams::EdDSA { ref curve, ref q } => f
                .debug_struct("PublicParams::EdDSA")
                .field("curve", curve)
                .field("q", &hex::encode(q))
                .finish(),
        }
    }
}
