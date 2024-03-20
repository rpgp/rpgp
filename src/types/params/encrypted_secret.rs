use std::{fmt, io};

use byteorder::{BigEndian, ByteOrder};
use digest::Digest;

use crate::crypto::checksum;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::ser::Serialize;
use crate::types::*;

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecretParams {
    /// The encrypted data, including the checksum.
    data: Vec<u8>,
    /// S2k Params
    s2k_params: S2kParams,
}

impl EncryptedSecretParams {
    pub fn new(data: Vec<u8>, s2k_params: S2kParams) -> Self {
        assert_ne!(s2k_params, S2kParams::Unprotected, "invalid string to key");
        EncryptedSecretParams { data, s2k_params }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn string_to_key_id(&self) -> u8 {
        (&self.s2k_params).into()
    }

    pub fn string_to_key_params(&self) -> &S2kParams {
        &self.s2k_params
    }

    pub fn checksum(&self) -> Vec<u8> {
        match self.s2k_params {
            S2kParams::Unprotected => unreachable!(),
            S2kParams::LegacyCfb { .. }
            | S2kParams::Aead { .. }
            | S2kParams::MaleableCfb { .. } => {
                // 2 octets
                self.data[self.data.len() - 2..].to_vec()
            }
            S2kParams::Cfb { .. } => {
                // 20 octets SHA1
                self.data[self.data.len() - 20..].to_vec()
            }
        }
    }

    pub fn unlock<F>(
        &self,
        pw: F,
        alg: PublicKeyAlgorithm,
        params: &PublicParams,
    ) -> Result<PlainSecretParams>
    where
        F: FnOnce() -> String,
    {
        match &self.s2k_params {
            S2kParams::Unprotected => unreachable!(),
            S2kParams::LegacyCfb { sym_alg, iv } => {
                let key = md5::Md5::digest(&pw());

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, &iv, &mut plaintext)?;

                // Checksum
                if plaintext.len() < 2 {
                    return Err(Error::InvalidInput);
                }
                let (plaintext, checksum) = plaintext.split_at(self.data.len() - 2);

                let calculated_checksum = checksum::calculate_simple(plaintext);
                if calculated_checksum != BigEndian::read_u16(checksum) {
                    return Err(Error::InvalidInput);
                }

                PlainSecretParams::from_slice(&plaintext, alg, params)
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;
                let mut plaintext = self.data.clone();
                todo!()
            }
            S2kParams::Cfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, &iv, &mut plaintext)?;

                // Checksum

                // Check SHA-1 hash if it is present.
                // See RFC 4880, "5.5.3 Secret-Key Packet Formats" for details.
                if plaintext.len() < 20 {
                    return Err(Error::InvalidInput);
                }

                let (plaintext, expected_sha1) = plaintext.split_at(self.data.len() - 20);
                let calculated_sha1 = checksum::calculate_sha1([plaintext]);
                if expected_sha1 != calculated_sha1 {
                    return Err(Error::InvalidInput);
                }
                PlainSecretParams::from_slice(&plaintext, alg, params)
            }
            S2kParams::MaleableCfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, &iv, &mut plaintext)?;
                if plaintext.len() < 2 {
                    return Err(Error::InvalidInput);
                }

                // Checksum
                let (plaintext, checksum) = plaintext.split_at(self.data.len() - 2);
                let calculated_checksum = checksum::calculate_simple(plaintext);
                if calculated_checksum != BigEndian::read_u16(checksum) {
                    return Err(Error::InvalidInput);
                }

                PlainSecretParams::from_slice(&plaintext, alg, params)
            }
        }
    }
}

impl Serialize for EncryptedSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[(&self.s2k_params).into()])?;

        match &self.s2k_params {
            S2kParams::Unprotected => {
                panic!("encrypted secret params should not have an unecrypted identifier")
            }
            S2kParams::LegacyCfb { ref iv, .. } => {
                writer.write_all(iv)?;
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                ref nonce,
            } => {
                writer.write_all(&[u8::from(*sym_alg)])?;
                writer.write_all(&[u8::from(*aead_mode)])?;
                s2k.to_writer(writer)?;
                writer.write_all(nonce)?;
            }
            S2kParams::Cfb {
                sym_alg,
                s2k,
                ref iv,
            }
            | S2kParams::MaleableCfb {
                sym_alg,
                s2k,
                ref iv,
            } => {
                writer.write_all(&[u8::from(*sym_alg)])?;
                s2k.to_writer(writer)?;
                writer.write_all(iv)?;
            }
        }

        writer.write_all(&self.data)?;

        Ok(())
    }
}

impl fmt::Debug for EncryptedSecretParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecretParams")
            .field("data", &hex::encode(&self.data))
            .field("string_to_key_params", &self.s2k_params)
            .finish()
    }
}
