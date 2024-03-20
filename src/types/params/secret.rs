use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{cond, map, map_res, rest_len, success};
use nom::multi::length_data;
use nom::number::streaming::be_u8;
use zeroize::Zeroize;

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
        let (_, (params, cs)) = parse_secret_fields(alg, params)(data)?;

        params.compare_checksum(cs)?;

        Ok(params)
    }

    pub fn string_to_key_id(&self) -> u8 {
        match self {
            SecretParams::Plain(k) => k.string_to_key_id(),
            SecretParams::Encrypted(k) => k.string_to_key_id(),
        }
    }

    pub fn compare_checksum(&self, other: Option<&[u8]>) -> Result<()> {
        match self {
            SecretParams::Plain(k) => k.as_ref().compare_checksum_simple(other),
            SecretParams::Encrypted(k) => k.compare_checksum(other),
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

/// Parse possibly encrypted private fields of a key.
fn parse_secret_fields(
    alg: PublicKeyAlgorithm,
    public_params: &PublicParams,
) -> impl Fn(&[u8]) -> IResult<&[u8], (SecretParams, Option<&[u8]>)> + '_ {
    move |i: &[u8]| {
        let (i, s2k_typ) = be_u8(i)?;
        let (i, enc_params) = match s2k_typ {
            // 0 is no encryption
            0 => (i, (None, None, None)),
            // symmetric key algorithm
            1..=252 => {
                let (i, sym_alg) = map_res(success(s2k_typ), SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (i, (Some(sym_alg), Some(iv), None))
            }
            253 => {
                let (i, sym_alg) = map_res(success(s2k_typ), SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (i, (Some(sym_alg), Some(iv), None))
            }
            // symmetric key + string-to-key
            254 => {
                let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, s2k) = s2k_parser(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (i, (Some(sym_alg), Some(iv), Some(s2k)))
            }
            255 => {
                let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
                let (i, s2k) = s2k_parser(i)?;
                let (i, iv) = take(sym_alg.block_size())(i)?;
                (i, (Some(sym_alg), Some(iv), Some(s2k)))
            }
        };
        let checksum_len = match s2k_typ {
            // 20 octect hash at the end, but part of the encrypted part
            254 => 0,
            // 2 octet checksum at the end
            _ => 2,
        };
        let (i, data) = length_data(map(rest_len, |r| r - checksum_len))(i)?;
        let (i, checksum) = cond(checksum_len > 0, take(checksum_len))(i)?;
        Ok((i, {
            let encryption_algorithm = enc_params.0;
            let iv = enc_params.1.map(|iv| iv.to_vec());
            let string_to_key = enc_params.2;
            let s2k_usage = S2kUsage::from(s2k_typ);

            let res = match s2k_typ {
                0 => {
                    let repr = PlainSecretParams::from_slice(data, alg, public_params)?;
                    SecretParams::Plain(repr)
                }
                _ => SecretParams::Encrypted(EncryptedSecretParams::new(
                    data.to_vec(),
                    iv.expect("encrypted"),
                    encryption_algorithm.expect("encrypted"),
                    string_to_key.expect("encrypted"),
                    s2k_usage,
                )),
            };
            (res, checksum)
        }))
    }
}
