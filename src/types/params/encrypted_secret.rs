use std::{fmt, io};

use byteorder::{BigEndian, ByteOrder};

use crypto::checksum;
use crypto::public_key::PublicKeyAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use ser::Serialize;
use types::*;

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

impl EncryptedSecretParams {
    pub fn new(
        data: Vec<u8>,
        iv: Vec<u8>,
        alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        id: u8,
    ) -> Self {
        assert_ne!(id, 0, "invalid string to key id");
        EncryptedSecretParams {
            data,
            iv,
            encryption_algorithm: alg,
            string_to_key: s2k,
            string_to_key_id: id,
        }
    }

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

    pub fn compare_checksum(&self, other: Option<&[u8]>) -> Result<()> {
        if self.string_to_key_id < 254 {
            if let Some(other) = other {
                ensure_eq!(
                    BigEndian::read_u16(other),
                    checksum::calculate_simple(self.data()),
                    "Invalid checksum"
                );
            } else {
                bail!("Missing checksum");
            }
        } else {
            ensure!(other.is_none(), "Expected no checksum, but found one");
        }

        Ok(())
    }

    pub fn checksum(&self) -> Option<Vec<u8>> {
        if self.string_to_key_id < 254 {
            Some(
                checksum::calculate_simple(self.data())
                    .to_be_bytes()
                    .to_vec(),
            )
        } else {
            None
        }
    }

    pub fn unlock<F>(&self, pw: F, alg: PublicKeyAlgorithm) -> Result<PlainSecretParams>
    where
        F: FnOnce() -> String,
    {
        let key = self
            .string_to_key
            .derive_key(&pw(), self.encryption_algorithm.key_size())?;

        // Actual decryption
        let mut plaintext = self.data.clone();
        self.encryption_algorithm
            .decrypt_with_iv_regular(&key, &self.iv, &mut plaintext)?;

        PlainSecretParams::from_slice(&plaintext, alg)
    }
}

impl Serialize for EncryptedSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.string_to_key_id])?;

        match self.string_to_key_id {
            0 => panic!("encrypted secret params should not have an unecrypted identifier"),
            1..=253 => {
                writer.write_all(&self.iv)?;
            }
            254..=255 => {
                let s2k = &self.string_to_key;

                writer.write_all(&[self.encryption_algorithm as u8])?;
                s2k.to_writer(writer)?;
                writer.write_all(&self.iv)?;
            }
        }

        writer.write_all(&self.data)?;
        if let Some(cs) = self.checksum() {
            writer.write_all(&cs)?;
        }

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
