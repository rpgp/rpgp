use std::io;
use std::io::Write;

use byteorder::{BigEndian, ByteOrder};
use digest::Digest;

use crate::crypto::checksum;
use crate::errors::{Error, Result};
use crate::ser::Serialize;
use crate::types::*;

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct EncryptedSecretParams {
    /// The encrypted data, including the checksum.
    #[debug("{}", hex::encode(data))]
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
        pub_key: &(impl PublicKeyTrait + Serialize),
        secret_type_id: Option<Tag>,
    ) -> Result<PlainSecretParams>
    where
        F: FnOnce() -> String,
    {
        // Argon2 is only used with AEAD (S2K usage octet 253).
        //
        // An implementation MUST NOT create and MUST reject as malformed any secret key packet
        // where the S2K usage octet is not AEAD (253) and the S2K specifier type is Argon2.
        match &self.s2k_params {
            S2kParams::Cfb { s2k, .. } | S2kParams::MaleableCfb { s2k, .. } => {
                if matches!(s2k, StringToKey::Argon2 { .. }) {
                    bail!(
                        "S2K method Argon2 is only allowed in combination with usage mode 'AEAD'"
                    );
                }
            }
            _ => {}
        }

        // For Version 6 keys: Additionally refuse legacy s2k mechanisms.
        // Those should never be generated or used.
        if pub_key.version() == KeyVersion::V6 {
            match &self.s2k_params {
                S2kParams::Aead { s2k, .. } | S2kParams::Cfb { s2k, .. } => {
                    match s2k {
                        StringToKey::Argon2 { .. }
                        | StringToKey::IteratedAndSalted { .. }
                        | StringToKey::Salted { .. } => {
                            // we'll allow these
                        }
                        _ => bail!("Version 6 keys may not use the weak S2k type {:?}", s2k),
                    }
                }
                _ => bail!("Version 6 keys may only be encrypted with S2k usage AEAD or CFB"),
            }
        }

        // We're willing to unlock.

        let alg = pub_key.algorithm();
        let params = pub_key.public_params();

        match &self.s2k_params {
            S2kParams::Unprotected => unreachable!(),
            S2kParams::LegacyCfb { sym_alg, iv } => {
                let key = md5::Md5::digest(pw());

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, iv, &mut plaintext)?;

                // Checksum
                if plaintext.len() < 2 {
                    return Err(Error::InvalidInput);
                }
                let (plaintext, checksum) = plaintext.split_at(self.data.len() - 2);

                let calculated_checksum = checksum::calculate_simple(plaintext);
                if calculated_checksum != BigEndian::read_u16(checksum) {
                    return Err(Error::InvalidInput);
                }

                PlainSecretParams::from_slice(plaintext, alg, params)
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            } => {
                match s2k {
                    StringToKey::Argon2 { .. } | StringToKey::IteratedAndSalted { .. } => {
                        // derive key
                        let derived = s2k.derive_key(&pw(), 32)?;

                        let Some(secret_type_id) = secret_type_id else {
                            bail!("no secret_type_id provided");
                        };

                        let (okm, ad) = s2k_usage_aead(
                            &derived,
                            secret_type_id,
                            pub_key,
                            *sym_alg,
                            *aead_mode,
                        )?;

                        // AEAD decrypt
                        let (ciphertext, tag) =
                            self.data.split_at(self.data.len() - aead_mode.tag_size());

                        let mut decrypt: Vec<_> = ciphertext.to_vec();
                        aead_mode.decrypt_in_place(sym_alg, &okm, nonce, &ad, tag, &mut decrypt)?;

                        // "decrypt" now contains the decrypted key material
                        PlainSecretParams::from_slice(&decrypt, alg, pub_key.public_params())
                    }

                    _ => bail!("S2K usage AEAD is not allowed with S2K type {:?}", s2k.id()),
                }
            }
            S2kParams::Cfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, iv, &mut plaintext)?;

                // Checksum

                // Check SHA-1 hash if it is present.
                // See RFC 4880, "5.5.3 Secret-Key Packet Formats" for details.
                if plaintext.len() < 20 {
                    return Err(Error::InvalidInput);
                }

                let (plaintext, expected_sha1) = plaintext.split_at(self.data.len() - 20);
                let calculated_sha1 = checksum::calculate_sha1([plaintext])?;
                if expected_sha1 != calculated_sha1 {
                    return Err(Error::InvalidInput);
                }
                PlainSecretParams::from_slice(plaintext, alg, params)
            }
            S2kParams::MaleableCfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, iv, &mut plaintext)?;
                if plaintext.len() < 2 {
                    return Err(Error::InvalidInput);
                }

                // Checksum
                let (plaintext, checksum) = plaintext.split_at(self.data.len() - 2);
                let calculated_checksum = checksum::calculate_simple(plaintext);
                if calculated_checksum != BigEndian::read_u16(checksum) {
                    return Err(Error::InvalidInput);
                }

                PlainSecretParams::from_slice(plaintext, alg, params)
            }
        }
    }

    pub(crate) fn to_writer<W: io::Write>(&self, w: &mut W, version: KeyVersion) -> Result<()> {
        w.write_all(&[(&self.s2k_params).into()])?;

        let mut s2k_params = vec![];

        let mut s2k_writer = &mut s2k_params;

        match &self.s2k_params {
            S2kParams::Unprotected => {
                panic!("encrypted secret params should not have an unencrypted identifier")
            }
            S2kParams::LegacyCfb { ref iv, .. } => {
                s2k_writer.write_all(iv)?;
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                ref nonce,
            } => {
                s2k_writer.write_all(&[u8::from(*sym_alg)])?;
                s2k_writer.write_all(&[u8::from(*aead_mode)])?;

                if version == KeyVersion::V6 {
                    s2k_writer.write_all(&[s2k.len()?])?; // length of S2K Specifier Type
                }
                s2k.to_writer(&mut s2k_writer)?;

                s2k_writer.write_all(nonce)?;
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
                s2k_writer.write_all(&[u8::from(*sym_alg)])?;

                if version == KeyVersion::V6 && matches!(self.s2k_params, S2kParams::Cfb { .. }) {
                    s2k_writer.write_all(&[s2k.len()?])?; // length of S2K Specifier Type
                }

                s2k.to_writer(&mut s2k_writer)?;

                s2k_writer.write_all(iv)?;
            }
        }

        if self.s2k_params != S2kParams::Unprotected {
            if version == KeyVersion::V6 {
                w.write_all(&[s2k_params.len().try_into().expect("FIXME")])?;
            }
            w.write_all(&s2k_params)?;
        }

        w.write_all(&self.data)?;

        Ok(())
    }
}
