use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{map_res, rest_len};
use nom::number::streaming::be_u8;
use zeroize::Zeroize;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::*;

/// A list of params that are used to represent the values of possibly encrypted key,
/// from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretParams {
    Plain(PlainSecretParams),
    Encrypted(EncryptedSecretParams),
}

impl Zeroize for SecretParams {
    fn zeroize(&mut self) {
        match self {
            SecretParams::Plain(p) => p.zeroize(),
            SecretParams::Encrypted(_) => { /* encrypted params do not need zeroing */ }
        }
    }
}

impl SecretParams {
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    pub fn from_slice(data: &[u8], alg: PublicKeyAlgorithm, params: &PublicParams) -> Result<Self> {
        let (_, params) = parse_secret_fields(alg, params)(data)?;
        Ok(params)
    }

    pub fn string_to_key_id(&self) -> u8 {
        match self {
            SecretParams::Plain(k) => k.string_to_key_id(),
            SecretParams::Encrypted(k) => k.string_to_key_id(),
        }
    }

    pub fn checksum(&self) -> Vec<u8> {
        match self {
            SecretParams::Plain(k) => k.checksum_simple(),
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

/// Parse possibly encrypted private fields of a key.
fn parse_secret_fields(
    alg: PublicKeyAlgorithm,
    public_params: &PublicParams,
) -> impl Fn(&[u8]) -> IResult<&[u8], SecretParams> + '_ {
    move |i: &[u8]| {
        let (i, s2k_usage) = map_res(be_u8, S2kUsage::try_from)(i)?;
        let (i, enc_params) = match s2k_usage {
            // 0 is no encryption
            S2kUsage::Unprotected => (i, S2kParams::Unprotected),
            // symmetric key algorithm
            S2kUsage::LegacyCfb(sym_alg) => {
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (
                    i,
                    S2kParams::LegacyCfb {
                        sym_alg,
                        iv: iv.to_vec(),
                    },
                )
            }
            S2kUsage::Aead => {
                let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, aead_mode) = map_res(be_u8, AeadAlgorithm::try_from)(i)?;
                let (i, s2k) = s2k_parser(i)?;
                let (i, nonce) = take(aead_mode.nonce_size())(i)?;
                (
                    i,
                    S2kParams::Aead {
                        sym_alg,
                        aead_mode,
                        s2k,
                        nonce: nonce.to_vec(),
                    },
                )
            }
            // symmetric key + string-to-key
            S2kUsage::Cfb => {
                let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, s2k) = s2k_parser(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (
                    i,
                    S2kParams::Cfb {
                        sym_alg,
                        s2k,
                        iv: iv.to_vec(),
                    },
                )
            }
            S2kUsage::MalleableCfb => {
                let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, s2k) = s2k_parser(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (
                    i,
                    S2kParams::Cfb {
                        sym_alg,
                        s2k,
                        iv: iv.to_vec(),
                    },
                )
            }
        };

        let (i, len) = rest_len(i)?;
        let (i, data) = take(len)(i)?;

        let res = match s2k_usage {
            S2kUsage::Unprotected => {
                let repr = PlainSecretParams::from_slice(data, alg, public_params)?;
                SecretParams::Plain(repr)
            }
            _ => SecretParams::Encrypted(EncryptedSecretParams::new(data.to_vec(), enc_params)),
        };

        Ok((i, res))
    }
}
