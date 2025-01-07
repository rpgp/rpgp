use std::io;
use std::io::Write;

use byteorder::WriteBytesExt;
use digest::Digest;
use zeroize::ZeroizeOnDrop;

use crate::crypto::checksum;
use crate::errors::{Error, Result};
use crate::ser::Serialize;
use crate::types::*;

#[derive(Clone, PartialEq, Eq, derive_more::Debug, ZeroizeOnDrop)]
pub struct EncryptedSecretParams {
    /// The encrypted data, including the checksum.
    #[debug("{}", hex::encode(data))]
    data: Vec<u8>,
    /// S2k Params
    #[zeroize(skip)]
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
            | S2kParams::MalleableCfb { .. } => {
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
        secret_tag: Option<Tag>,
    ) -> Result<PlainSecretParams>
    where
        F: FnOnce() -> String,
    {
        // Argon2 is only used with AEAD (S2K usage octet 253).
        //
        // An implementation MUST NOT create and MUST reject as malformed any secret key packet
        // where the S2K usage octet is not AEAD (253) and the S2K specifier type is Argon2.
        //
        // Ref: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.2.1-10
        match &self.s2k_params {
            S2kParams::Cfb { s2k, .. } | S2kParams::MalleableCfb { s2k, .. } => {
                if matches!(s2k, StringToKey::Argon2 { .. }) {
                    bail!(
                        "S2k method Argon2 is only allowed in combination with usage mode 'AEAD'"
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
                            // we'll allow these, generally
                        }
                        _ => bail!("Version 6 keys may not use the weak S2k type {:?}", s2k),
                    }

                    // Implementations MUST NOT decrypt a secret using MD5, SHA-1, or RIPEMD-160
                    // as a hash function in an S2K KDF in a version 6 (or later) packet.
                    // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
                    ensure!(
                        !s2k.known_weak_hash_algo(),
                        "Weak hash algorithm in S2K not allowed for v6 {:?}",
                        s2k
                    )
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

                PlainSecretParams::try_from_slice(&plaintext, pub_key.version(), alg, params)
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            } => {
                match s2k {
                    StringToKey::Argon2 { .. } | StringToKey::IteratedAndSalted { .. } => {
                        let Some(tag_size) = aead_mode.tag_size() else {
                            unsupported_err!("AEAD mode: {:?}", aead_mode);
                        };

                        if self.data.len() < tag_size {
                            return Err(Error::InvalidInput);
                        }

                        // derive key
                        let derived = s2k.derive_key(&pw(), 32)?;

                        let Some(secret_tag) = secret_tag else {
                            bail!("no secret_tag provided");
                        };

                        let (okm, ad) =
                            s2k_usage_aead(&derived, secret_tag, pub_key, *sym_alg, *aead_mode)?;

                        // AEAD decrypt
                        let (ciphertext, tag) = self.data.split_at(self.data.len() - tag_size);

                        let mut decrypt: Vec<_> = ciphertext.to_vec();
                        aead_mode.decrypt_in_place(sym_alg, &okm, nonce, &ad, tag, &mut decrypt)?;

                        // "decrypt" now contains the decrypted key material
                        PlainSecretParams::try_from_slice_no_checksum(
                            &decrypt,
                            pub_key.version(),
                            alg,
                            pub_key.public_params(),
                        )
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
                // See <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3-3.5.1> for details.
                if plaintext.len() < 20 {
                    return Err(Error::InvalidInput);
                }

                let (plaintext, expected_sha1) = plaintext.split_at(self.data.len() - 20);
                let calculated_sha1 = checksum::calculate_sha1([plaintext])?;
                if expected_sha1 != calculated_sha1 {
                    return Err(Error::InvalidInput);
                }
                PlainSecretParams::try_from_slice_no_checksum(
                    plaintext,
                    pub_key.version(),
                    alg,
                    params,
                )
            }
            S2kParams::MalleableCfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(&pw(), sym_alg.key_size())?;

                // Decryption
                let mut plaintext = self.data.clone();
                sym_alg.decrypt_with_iv_regular(&key, iv, &mut plaintext)?;
                if plaintext.len() < 2 {
                    return Err(Error::InvalidInput);
                }

                PlainSecretParams::try_from_slice(&plaintext, pub_key.version(), alg, params)
            }
        }
    }

    pub(crate) fn to_writer<W: io::Write>(
        &self,
        writer: &mut W,
        version: KeyVersion,
    ) -> Result<()> {
        writer.write_u8((&self.s2k_params).into())?;

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
                s2k_writer.write_u8((*sym_alg).into())?;
                s2k_writer.write_u8((*aead_mode).into())?;

                if version == KeyVersion::V6 {
                    s2k_writer.write_u8(s2k.len()?)?; // length of S2K Specifier Type
                }
                s2k.to_writer(&mut s2k_writer)?;

                s2k_writer.write_all(nonce)?;
            }
            S2kParams::Cfb {
                sym_alg,
                s2k,
                ref iv,
            }
            | S2kParams::MalleableCfb {
                sym_alg,
                s2k,
                ref iv,
            } => {
                s2k_writer.write_u8((*sym_alg).into())?;

                if version == KeyVersion::V6 && matches!(self.s2k_params, S2kParams::Cfb { .. }) {
                    s2k_writer.write_u8(s2k.len()?)?; // length of S2K Specifier Type
                }

                s2k.to_writer(&mut s2k_writer)?;

                s2k_writer.write_all(iv)?;
            }
        }

        if self.s2k_params != S2kParams::Unprotected {
            if version == KeyVersion::V6 {
                let len = s2k_params.len();
                ensure!(len <= 255, "unexpected s2k_params length {}", len);

                writer.write_u8(len.try_into()?)?;
            }
            writer.write_all(&s2k_params)?;
        }

        writer.write_all(&self.data)?;

        Ok(())
    }

    pub(crate) fn write_len(&self, version: KeyVersion) -> usize {
        let mut sum = 1;
        match &self.s2k_params {
            S2kParams::Unprotected => {
                panic!("encrypted secret params should not have an unencrypted identifier")
            }
            S2kParams::LegacyCfb { ref iv, .. } => {
                sum += iv.len();
            }
            S2kParams::Aead { s2k, ref nonce, .. } => {
                sum += 1 + 1;

                if version == KeyVersion::V6 {
                    sum += 1;
                }
                sum += s2k.write_len();
                sum += nonce.len();
            }
            S2kParams::Cfb { s2k, ref iv, .. } | S2kParams::MalleableCfb { s2k, ref iv, .. } => {
                sum += 1;
                if version == KeyVersion::V6 && matches!(self.s2k_params, S2kParams::Cfb { .. }) {
                    sum += 1;
                }

                sum += s2k.write_len();
                sum += iv.len();
            }
        }

        if self.s2k_params != S2kParams::Unprotected && version == KeyVersion::V6 {
            sum += 1;
        }

        sum += self.data.len();
        sum
    }
}
