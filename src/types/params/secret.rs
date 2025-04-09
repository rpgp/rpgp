use std::io::{self, BufRead};

use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{aead::AeadAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    types::*,
};

/// A list of params that are used to represent the values of possibly encrypted key,
/// from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
#[allow(clippy::large_enum_variant)]
pub enum SecretParams {
    Plain(PlainSecretParams),
    Encrypted(EncryptedSecretParams),
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
        let params = parse_secret_fields(key_ver, alg, params, data)?;

        // Version 6 secret keys may only use "S2K Usage" 0, 253 or 254
        //
        // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.2.1-8
        if key_ver == KeyVersion::V6 && ![0, 253, 254].contains(&params.string_to_key_id()) {
            bail!(
                "Illegal S2K Usage setting {} for a V6 key",
                params.string_to_key_id()
            )
        }

        Ok(params)
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.string_to_key_id() == 254
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
            SecretParams::Plain(k) => {
                writer.write_all(&[k.string_to_key_id()])?;
                k.to_writer(writer, version)
            }
            SecretParams::Encrypted(k) => k.to_writer(writer, version),
        }
    }

    pub fn write_len(&self, version: KeyVersion) -> usize {
        match self {
            SecretParams::Plain(k) => {
                let mut sum = 1; // s2k usage unprotected
                sum += k.write_len(version);
                sum
            }
            SecretParams::Encrypted(k) => k.write_len(version),
        }
    }
}

/// Parse possibly encrypted private fields of a key.
fn parse_secret_fields<B: BufRead>(
    key_ver: KeyVersion,
    alg: PublicKeyAlgorithm,
    public_params: &PublicParams,
    mut i: B,
) -> Result<SecretParams> {
    // We've already consumed the public fields, and have arrived at the private key-specific
    // part of this secret key packet
    // (see https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats)

    let s2k_usage = i.read_u8().map(S2kUsage::from)?;

    // TODO: use s2k_len
    let _s2k_len = if key_ver == KeyVersion::V6 && s2k_usage != S2kUsage::Unprotected {
        // Only for a version 6 packet where the secret key material is encrypted (that is,
        // where the previous octet is not zero), a 1-octet scalar octet count of the
        // cumulative length of all the following conditionally included S2K parameter fields.
        let len = i.read_u8()?;
        if len == 0 {
            return Err(InvalidInputSnafu.build());
        }
        Some(len)
    } else {
        None
    };

    let enc_params = match s2k_usage {
        // 0 is no encryption
        S2kUsage::Unprotected => S2kParams::Unprotected,
        // symmetric key algorithm
        S2kUsage::LegacyCfb(sym_alg) => {
            let iv = i.take_bytes(sym_alg.block_size())?.freeze();
            S2kParams::LegacyCfb { sym_alg, iv }
        }
        S2kUsage::Aead => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
            let aead_mode = i.read_u8().map(AeadAlgorithm::from)?;

            let len = if key_ver == KeyVersion::V6 {
                // Only for a version 6 packet, and if the S2K usage octet was 253 or 254,
                // a 1-octet count of the size of the one field following this octet.
                i.read_u8().map(Some)?
            } else {
                None
            };

            let s2k = StringToKey::try_from_reader(&mut i)?;

            // if we got a length field (in v6), check that it contained a consistent value
            if let Some(len) = len {
                if s2k.len()? != len {
                    bail!(
                        "String2Key length {} doesn't match for s2k type {:?}",
                        len,
                        s2k
                    );
                }
            }

            let nonce = i.take_bytes(aead_mode.nonce_size())?.freeze();

            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            }
        }
        // symmetric key + string-to-key
        S2kUsage::Cfb => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;

            let len = if key_ver == KeyVersion::V6 {
                // Only for a version 6 packet, and if the S2K usage octet was 253 or 254,
                // a 1-octet count of the size of the one field following this octet.
                i.read_u8().map(Some)?
            } else {
                None
            };

            let s2k = StringToKey::try_from_reader(&mut i)?;

            // if we got a length field (in v6), check that it contained a consistent value
            if let Some(len) = len {
                if s2k.len()? != len {
                    bail!(
                        "String2Key length {} doesn't match for s2k type {:?}",
                        len,
                        s2k
                    );
                }
            }

            let iv = i.take_bytes(sym_alg.block_size())?.freeze();
            S2kParams::Cfb { sym_alg, s2k, iv }
        }
        S2kUsage::MalleableCfb => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
            let s2k = StringToKey::try_from_reader(&mut i)?;
            let iv = i.take_bytes(sym_alg.block_size())?.freeze();

            S2kParams::Cfb { sym_alg, s2k, iv }
        }
    };

    match s2k_usage {
        S2kUsage::Unprotected => {
            let params = PlainSecretParams::try_from_reader(i, key_ver, alg, public_params)?;
            Ok(SecretParams::Plain(params))
        }
        _ => {
            let params = EncryptedSecretParams::new(i.rest()?.freeze(), enc_params);
            Ok(SecretParams::Encrypted(params))
        }
    }
}
