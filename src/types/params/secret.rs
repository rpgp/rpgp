use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{map, map_res, rest_len};
use nom::number::streaming::be_u8;
use zeroize::Zeroize;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
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

    pub fn from_slice(
        data: &[u8],
        key_ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        params: &PublicParams,
    ) -> Result<Self> {
        let (_, params) = parse_secret_fields(key_ver, alg, params)(data)?;
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

    pub fn to_writer<W: io::Write>(&self, writer: &mut W, version: KeyVersion) -> Result<()> {
        match self {
            SecretParams::Plain(k) => k.to_writer(writer, version),
            SecretParams::Encrypted(k) => k.to_writer(writer, version),
        }
    }
}

/// Parse possibly encrypted private fields of a key.
fn parse_secret_fields(
    key_ver: KeyVersion,
    alg: PublicKeyAlgorithm,
    public_params: &PublicParams,
) -> impl Fn(&[u8]) -> IResult<&[u8], SecretParams> + '_ {
    move |i: &[u8]| {
        // We've already consumed the public fields, and have arrived at the private key-specific
        // part of this secret key packet
        // (see https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats)

        let (i, s2k_usage) = map_res(be_u8, S2kUsage::try_from)(i)?;

        // FIXME: use s2k_len
        let (i, s2k_len) = if key_ver == KeyVersion::V6 && s2k_usage != S2kUsage::Unprotected {
            // Only for a version 6 packet where the secret key material is encrypted (that is,
            // where the previous octet is not zero), a 1-octet scalar octet count of the
            // cumulative length of all the following conditionally included S2K parameter fields.
            map(be_u8, Some)(i)?
        } else {
            (i, None)
        };

        // expected length of the remaining data after consuming the conditionally included
        // s2k parameter fields
        let after_s2k = s2k_len.map(|len| i.len() - len as usize);

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

                let (i, len) = if key_ver == KeyVersion::V6 {
                    // Only for a version 6 packet, and if the S2K usage octet was 253 or 254,
                    // a 1-octet count of the size of the one field following this octet.
                    map(be_u8, Some)(i)?
                } else {
                    (i, None)
                };

                let (i, s2k) = s2k_parser(i)?;

                // if we got a length field (in v6), check that it contained a consistent value
                if let Some(len) = len {
                    if s2k.len()? != len {
                        return Err(nom::Err::Error(crate::errors::Error::Message(format!(
                            "String2Key length {} doesn't match for s2k type {:?}",
                            len, s2k
                        ))));
                    }
                }

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

                let (i, len) = if key_ver == KeyVersion::V6 {
                    // Only for a version 6 packet, and if the S2K usage octet was 253 or 254,
                    // a 1-octet count of the size of the one field following this octet.
                    map(be_u8, Some)(i)?
                } else {
                    (i, None)
                };

                let (i, s2k) = s2k_parser(i)?;

                // if we got a length field (in v6), check that it contained a consistent value
                if let Some(len) = len {
                    if s2k.len()? != len {
                        return Err(nom::Err::Error(crate::errors::Error::Message(format!(
                            "String2Key length {} doesn't match for s2k type {:?}",
                            len, s2k
                        ))));
                    }
                }

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

        if let Some(after_s2k) = after_s2k {
            if i.len() != after_s2k {
                return Err(nom::Err::Error(crate::errors::Error::Message(
                    "Unexpected length of S2K parameter fields".to_string(),
                )));
            }
        }

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
