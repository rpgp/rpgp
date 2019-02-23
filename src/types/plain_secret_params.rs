use std::{fmt, io};

use num_bigint::BigUint;
use rsa::RSAPrivateKey;

use crypto::checksum;
use crypto::ecc_curve::ECCCurve;
use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use errors::Result;
use ser::Serialize;
use types::*;
use util::{mpi, mpi_big, write_bignum_mpi, write_mpi};

#[derive(Clone, PartialEq, Eq)]
pub enum PlainSecretParams {
    RSA {
        d: BigUint,
        p: BigUint,
        q: BigUint,
        u: BigUint,
    },
    DSA(BigUint),
    ECDSA(Vec<u8>),
    ECDH(Vec<u8>),
    Elgamal(BigUint),
    EdDSA(Vec<u8>),
}

impl PlainSecretParams {
    pub fn from_slice(data: &[u8], alg: PublicKeyAlgorithm) -> Result<Self> {
        let (_, repr) = parse_secret_params(data, alg)?;

        Ok(repr)
    }

    pub fn string_to_key_id(&self) -> u8 {
        0
    }

    fn to_writer_raw<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PlainSecretParams::RSA { d, p, q, u } => {
                write_bignum_mpi(d, writer)?;
                write_bignum_mpi(p, writer)?;
                write_bignum_mpi(q, writer)?;
                write_bignum_mpi(u, writer)?;
            }
            PlainSecretParams::DSA(x) => {
                write_bignum_mpi(x, writer)?;
            }
            PlainSecretParams::ECDSA(x) => {
                write_mpi(x, writer)?;
            }
            PlainSecretParams::ECDH(x) => {
                write_mpi(x, writer)?;
            }
            PlainSecretParams::Elgamal(d) => {
                write_bignum_mpi(d, writer)?;
            }
            PlainSecretParams::EdDSA(x) => {
                write_mpi(x, writer)?;
            }
        }

        Ok(())
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_simple(&buf)
    }

    pub fn checksum_sha1(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_sha1(&buf)
    }

    pub fn as_repr(&self, public_params: &PublicParams) -> Result<SecretKeyRepr> {
        match self {
            PlainSecretParams::RSA { d, p, q, .. } => match public_params {
                PublicParams::RSA { ref n, ref e } => {
                    let secret_key = RSAPrivateKey::from_components(
                        n.clone(),
                        e.clone(),
                        d.clone(),
                        vec![p.clone(), q.clone()],
                    );
                    secret_key.validate()?;
                    Ok(SecretKeyRepr::RSA(secret_key))
                }
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParams::ECDH(d) => match public_params {
                PublicParams::ECDH {
                    ref curve,
                    ref hash,
                    ref alg_sym,
                    ..
                } => match *curve {
                    ECCCurve::Curve25519 => {
                        ensure_eq!(d.len(), 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(d);

                        Ok(SecretKeyRepr::ECDH(ECDHSecretKey {
                            oid: curve.oid(),
                            hash: *hash,
                            alg_sym: *alg_sym,
                            secret,
                        }))
                    }
                    _ => unsupported_err!("curve {:?} for ECDH", curve.to_string()),
                },
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParams::EdDSA(d) => match public_params {
                PublicParams::EdDSA { ref curve, .. } => match *curve {
                    ECCCurve::Ed25519 => {
                        ensure_eq!(d.len(), 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(d);

                        Ok(SecretKeyRepr::EdDSA(EdDSASecretKey {
                            oid: curve.oid(),
                            secret,
                        }))
                    }
                    _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                },
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParams::DSA(_) => {
                unimplemented_err!("DSA");
            }
            PlainSecretParams::Elgamal(_) => {
                unimplemented_err!("Elgamal");
            }
            PlainSecretParams::ECDSA(_) => {
                unimplemented_err!("ECDSA");
            }
        }
    }
}

impl Serialize for PlainSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.string_to_key_id()])?;
        let mut buf = Vec::new();
        self.to_writer_raw(&mut buf)?;
        writer.write_all(&buf)?;
        writer.write_all(&checksum::calculate_simple(&buf))?;

        Ok(())
    }
}

impl fmt::Debug for PlainSecretParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PlainSecretParams::RSA { .. } => write!(f, "PlainSecretParams(RSA)"),
            PlainSecretParams::DSA(_) => write!(f, "PlainSecretParams(DSA)"),
            PlainSecretParams::Elgamal(_) => write!(f, "PlainSecretParams(Elgamal)"),
            PlainSecretParams::ECDSA(_) => write!(f, "PlainSecretParams(ECDSA)"),
            PlainSecretParams::ECDH(_) => write!(f, "PlainSecretParams(ECDH)"),
            PlainSecretParams::EdDSA(_) => write!(f, "PlainSecretParams(EdDSA)"),
        }
    }
}

#[rustfmt::skip]
named_args!(parse_secret_params(alg: PublicKeyAlgorithm) <PlainSecretParams>, switch!(value!(alg),
    PublicKeyAlgorithm::RSA        |
    PublicKeyAlgorithm::RSAEncrypt |
    PublicKeyAlgorithm::RSASign => call!(rsa_secret_params)                                |
    PublicKeyAlgorithm::DSA     => do_parse!(x: mpi_big >> (PlainSecretParams::DSA(x)))      |
    PublicKeyAlgorithm::Elgamal => do_parse!(x: mpi_big >> (PlainSecretParams::Elgamal(x)))  |
    PublicKeyAlgorithm::ECDH    => do_parse!(x: mpi >> (PlainSecretParams::ECDH(x.into())))  |
    PublicKeyAlgorithm::ECDSA   => do_parse!(x: mpi >> (PlainSecretParams::ECDSA(x.into()))) |
    PublicKeyAlgorithm::EdDSA   => do_parse!(x: mpi >> (PlainSecretParams::EdDSA(x.into())))
));

/// Parse the decrpyted private params of an RSA private key.
#[rustfmt::skip]
named!(rsa_secret_params<PlainSecretParams>, do_parse!(
       d: mpi_big
    >> p: mpi_big
    >> q: mpi_big
    >> u: mpi_big
    >> (PlainSecretParams::RSA { d, p, q, u })
));
