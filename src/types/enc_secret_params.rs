use std::{fmt, io};

use nom::{be_u8, rest_len};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rsa::RSAPrivateKey;

use crypto::checksum;
use crypto::ecc_curve::ECCCurve;
use crypto::kdf;
use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use ser::Serialize;
use types::*;
use util::{mpi, mpi_big, write_bignum_mpi, write_mpi};

/// A list of params that are used to represent the values of possibly encrypted key,
/// from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretParams {
    Plain(PlainSecretParams),
    Encrypted(EncryptedSecretParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecretParams {
    /// The encrypted data.
    data: Vec<u8>,
    /// IV.
    iv: Vec<u8>,
    /// The encryption algorithm used.
    encryption_algorithm: SymmetricKeyAlgorithm,
    /// The string-to-key method and its parameters.
    string_to_key: StringToKey,
    /// The identifier for how this data is stored.
    string_to_key_id: u8,
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

impl EncryptedSecretParams {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn encryption_algorithm(&self) -> SymmetricKeyAlgorithm {
        self.encryption_algorithm
    }

    pub fn string_to_key(&self) -> &StringToKey {
        &self.string_to_key
    }

    pub fn string_to_key_id(&self) -> u8 {
        self.string_to_key_id
    }

    pub fn checksum(&self) -> Option<Vec<u8>> {
        if self.string_to_key_id < 254 {
            Some(checksum::calculate_simple(self.data()))
        } else {
            None
        }
    }

    pub fn unlock<F>(&self, pw: F, alg: PublicKeyAlgorithm) -> Result<PlainSecretParams>
    where
        F: FnOnce() -> String,
    {
        let s2k_details = &self.string_to_key;
        let key = kdf::s2k(
            pw,
            self.encryption_algorithm,
            s2k_details.typ(),
            s2k_details.hash(),
            s2k_details.salt(),
            s2k_details.count(),
        )?;

        let iv = &self.iv;

        // Actual decryption
        let mut plaintext = self.data.clone();
        self.encryption_algorithm
            .decrypt_with_iv_regular(&key, iv, &mut plaintext)?;

        PlainSecretParams::from_slice(&plaintext, alg)
    }
}

impl SecretParams {
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    pub fn from_slice(data: &[u8], alg: PublicKeyAlgorithm) -> Result<Self> {
        let (_, (params, cs)) = parse_secret_fields(data, alg)?;

        let other = params.checksum();
        ensure_eq!(cs, other.as_ref().map(|v| &v[..]), "invalid checksum");

        Ok(params)
    }

    pub fn string_to_key_id(&self) -> u8 {
        match self {
            SecretParams::Plain(k) => k.string_to_key_id(),
            SecretParams::Encrypted(k) => k.string_to_key_id(),
        }
    }

    pub fn checksum(&self) -> Option<Vec<u8>> {
        match self {
            SecretParams::Plain(k) => Some(k.checksum_simple()),
            SecretParams::Encrypted(k) => k.checksum(),
        }
    }
}

impl Serialize for SecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            SecretParams::Plain(k) => k.to_writer(writer),
            SecretParams::Encrypted(k) => k.to_writer(writer),
        }
    }
}

impl Serialize for EncryptedSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.string_to_key_id])?;

        match self.string_to_key_id {
            0 => panic!("encrypted secret params should not have an unecrypted identifier"),
            1...253 => {
                writer.write_all(&self.iv)?;
            }
            254...255 => {
                let s2k = &self.string_to_key;

                writer.write_all(&[self.encryption_algorithm as u8])?;
                s2k.to_writer(writer)?;
                writer.write_all(&self.iv)?;
            }
            _ => unreachable!("this is a u8"),
        }

        writer.write_all(&self.data)?;
        if let Some(cs) = self.checksum() {
            writer.write_all(&cs)?;
        }

        Ok(())
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

impl fmt::Debug for EncryptedSecretParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EncryptedSecretParams")
            .field("data", &hex::encode(&self.data))
            .field("checksum", &self.checksum().map(hex::encode))
            .field("iv", &hex::encode(&self.iv))
            .field("encryption_algorithm", &self.encryption_algorithm)
            .field("string_to_key", &self.string_to_key)
            .field("string_to_key_id", &self.string_to_key_id)
            .finish()
    }
}

/// Parse possibly encrypted private fields of a key.
#[rustfmt::skip]
named_args!(parse_secret_fields(alg: PublicKeyAlgorithm) <(SecretParams, Option<&[u8]>)>, do_parse!(
          s2k_typ: be_u8
    >> enc_params: switch!(value!(s2k_typ),
                   // 0 is no encryption
                   0       => value!((None, None, None)) |
                   // symmetric key algorithm
                   1...253 => do_parse!(
                          sym_alg: map_opt!(
                                    value!(s2k_typ),
                                    SymmetricKeyAlgorithm::from_u8
                                )
                       >>      iv: take!(sym_alg.block_size())
                       >> (Some(sym_alg), Some(iv), None)
                   ) |
                   // symmetric key + string-to-key
                   254...255 => do_parse!(
                             sym_alg: map_opt!(
                                        be_u8,
                                        SymmetricKeyAlgorithm::from_u8
                                      )
                       >>        s2k: s2k_parser
                       >>         iv: take!(sym_alg.block_size())
                       >> (Some(sym_alg), Some(iv), Some(s2k))
                   )
    )
    >> checksum_len: switch!(value!(s2k_typ),
        // 20 octect hash at the end, but part of the encrypted part
        254 => value!(0) |
        // 2 octet checksum at the end
        _   => value!(2)
    )
    >> data_len: map!(rest_len, |r| r - checksum_len)
    >>     data: take!(data_len)
    >> checksum: cond!(checksum_len > 0, take!(checksum_len))
    >> ({
        let encryption_algorithm = enc_params.0;
        let iv = enc_params.1.map(|iv| iv.to_vec());
        let string_to_key = enc_params.2;

        let res = match s2k_typ {
            0 => {
                let repr = PlainSecretParams::from_slice(data, alg)?;
                SecretParams::Plain(repr)
            }
            _ => {
                SecretParams::Encrypted(EncryptedSecretParams {
                    data: data.to_vec(),
                    iv: iv.expect("encrypted"),
                    encryption_algorithm: encryption_algorithm.expect("encrypted"),
                    string_to_key: string_to_key.expect("encrypted"),
                    string_to_key_id: s2k_typ,
                })
            }
        };
        (res, checksum)
    })
));

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
