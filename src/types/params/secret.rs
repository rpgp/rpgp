use std::io;

use nom::{be_u8, rest_len};
use num_traits::FromPrimitive;
use zeroize::Zeroize;

use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
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
        let (_, (params, cs)) = parse_secret_fields(data, alg, params)?;

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

// Parse possibly encrypted private fields of a key.
#[rustfmt::skip]
fn parse_secret_fields<'a, 'b>(
    input: &'b [u8],
    alg: PublicKeyAlgorithm,
    public_params: &'a PublicParams,
) -> nom::IResult<&'b [u8], (SecretParams, Option<&'b [u8]>)> {
    do_parse!(input, 
              s2k_typ: be_u8
        >> enc_params: switch!(value!(s2k_typ),
                        // 0 is no encryption
                        0       => value!((None, None, None)) |
                        // symmetric key algorithm
                        1..=253 => do_parse!(
                                      sym_alg: map_opt!(value!(s2k_typ), SymmetricKeyAlgorithm::from_u8)
                                   >>      iv: take!(sym_alg.block_size())
                                   >> (Some(sym_alg), Some(iv), None)
                                   ) |
                       // symmetric key + string-to-key
                       254..=255 => do_parse!(
                                        sym_alg: map_opt!(be_u8,SymmetricKeyAlgorithm::from_u8)
                                    >>      s2k: s2k_parser
                                    >>       iv: take!(sym_alg.block_size())
                                    >> (Some(sym_alg), Some(iv), Some(s2k))
                                    )
                       )
        >> checksum_len:
                switch!(value!(s2k_typ),
                    // 20 octect hash at the end, but part of the encrypted part
                    254 => value!(0) |
                    // 2 octet checksum at the end
                    _   => value!(2)
                )
        >> data_len: map!(rest_len, |r| r - checksum_len)
        >> data: take!(data_len)
        >> checksum: cond!(checksum_len > 0, take!(checksum_len))
        >> ({
            let encryption_algorithm = enc_params.0;
            let iv = enc_params.1.map(|iv| iv.to_vec());
            let string_to_key = enc_params.2;

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
                    s2k_typ,
                )),
            };
            (res, checksum)
        })
    )
}
