#![cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys")]

//! Persistent Symmetric Key support
//!
//! <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html#name-algorithm-specific-fields-f>

use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::Sha512;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aead::AeadAlgorithm, sym::SymmetricKeyAlgorithm, Decryptor, HashAlgorithm},
    errors::{bail, ensure_eq, Result},
    packet::SignatureVersion,
    ser::Serialize,
    types::{PkeskVersion, SignatureBytes, Tag},
};

/// Secret key for AEAD persistent symmetric keys
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey {
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    pub(crate) key: Box<[u8]>, // must be sized to match the sym_alg
}

pub struct EncryptionFields<'a> {
    pub data: Bytes,
    pub sym_alg: SymmetricKeyAlgorithm,
    pub aead: AeadAlgorithm,
    pub version: PkeskVersion,
    pub salt: &'a [u8; 32],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct InfoParameter {
    pub packet_type: Tag,
    pub version: u8,
    pub sym_alg: SymmetricKeyAlgorithm,
    pub aead: AeadAlgorithm,
}

impl From<InfoParameter> for [u8; 4] {
    fn from(value: InfoParameter) -> Self {
        [
            value.packet_type.encode(),
            value.version,
            value.sym_alg.into(),
            value.aead.into(),
        ]
    }
}

impl SecretKey {
    /// Signing operation for persistent symmetric keys that exposes the full algorithmic flexibility
    pub fn sign_persistent_symmetric<RNG: Rng + CryptoRng>(
        &self,
        mut rng: RNG,
        version: SignatureVersion,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        hash: HashAlgorithm,
        digest: &[u8],
    ) -> Result<SignatureBytes> {
        let Some(digest_size) = hash.digest_size() else {
            bail!(
                "sign_persistent_symmetric: invalid hash algorithm: {:?}",
                hash
            );
        };
        ensure_eq!(
            digest.len(),
            digest_size,
            "Unexpected digest length {} for hash algorithm {:?}",
            digest.len(),
            hash,
        );

        let mut salt = [0; 32];
        rng.fill(&mut salt);

        let signature = self.calculate_signature(version, sym_alg, aead, &salt, digest)?;
        let tag = signature.to_vec().into();

        Ok(SignatureBytes::PersistentSymmetric { aead, salt, tag })
    }

    pub(crate) fn calculate_signature(
        &self,
        version: SignatureVersion,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        salt: &[u8; 32],
        digest: &[u8],
    ) -> Result<BytesMut> {
        let info = InfoParameter {
            packet_type: Tag::Signature,
            version: version.into(),
            sym_alg,
            aead,
        };

        let (key, iv) = Self::derive_key_iv(&self.key, salt, info);

        // An authentication tag of the size specified by the AEAD mode, created by encrypting the
        // empty value with the message authentication key and IV computed as described in Section
        // 7.4, using the symmetric-key cipher of the key and the indicated AEAD mode, with as
        // additional data the hash digest described in section 5.2.4 of [RFC9580].

        let mut buf = BytesMut::with_capacity(16); // pre-allocate tag size
        aead.encrypt_in_place(&sym_alg, &key, &iv, digest, &mut buf)?;
        Ok(buf)
    }

    /// Key and IV derivation
    /// <https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-03.html#name-key-and-iv-derivation>
    ///
    /// Returns:
    /// - M bits of key, matching the size of SymmetricKeyAlgorithm,
    /// - N bit of IV, matching the nonce size of AeadAlgorithm
    pub(crate) fn derive_key_iv(
        persistent_key: &[u8],
        salt: &[u8; 32],
        info: InfoParameter,
    ) -> (Zeroizing<Box<[u8]>>, Box<[u8]>) {
        let hk = Hkdf::<Sha512>::new(Some(salt), persistent_key);

        let key_size = info.sym_alg.key_size();
        let nonce_size = info.aead.nonce_size();

        // M + N bits are derived using HKDF.
        // The left-most M bits are used as symmetric algorithm key, the remaining N bits are
        // used as initialization vector.
        let mut output = Zeroizing::new(vec![0u8; key_size + nonce_size]);

        let info_parameter: [u8; 4] = info.into();
        hk.expand(&info_parameter, &mut output)
            .expect("expand size is < 255 * HashLength");

        let key: Box<[u8]> = output[0..key_size].into();
        let iv = output[key_size..].into();

        (key.into(), iv)
    }
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let info = InfoParameter {
            packet_type: Tag::PublicKeyEncryptedSessionKey,
            version: data.version.into(),
            sym_alg: data.sym_alg,
            aead: data.aead,
        };

        let (key, iv) = Self::derive_key_iv(&self.key, data.salt, info);

        let mut buf = data.data.into();

        data.aead
            .decrypt_in_place(&data.sym_alg, &key, &iv, &[], &mut buf)?;

        Ok(buf.to_vec().into())
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.key)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.len()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    use crate::{
        crypto::{
            aead_key::{AeadAlgorithm, InfoParameter, SecretKey},
            sym::SymmetricKeyAlgorithm,
        },
        types::Tag,
    };

    prop_compose! {
        pub fn key_gen()(seed: u64) -> Box<[u8]> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

            // Sized to match AES256 as sym alg
            // TODO: how to handle sym alg in proptests?
            let mut key :Box<[u8]>  = vec![0u8 ;32].into();

            rng.fill(&mut key[..]);

            key
        }
    }

    /// Key/IV derivation
    ///
    /// - persistent key: 16 bytes of 0x00
    /// - salt: 32 bytes of 0xff
    /// - info: Signature, Version 6, OCB, AES128
    #[test]
    fn psk_derive_key_iv() {
        const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

        let persistent_key = &[0; SYM_ALG.key_size()];
        let salt = &[0xff; 32];

        let (key, iv) = SecretKey::derive_key_iv(
            persistent_key,
            salt,
            InfoParameter {
                packet_type: Tag::Signature,
                version: 6,
                sym_alg: SYM_ALG,
                aead: AeadAlgorithm::Ocb,
            },
        );

        assert_eq!(
            **key,
            [
                0xc2, 0x41, 0x48, 0x69, 0x39, 0x9f, 0x5c, 0x53, 0xbb, 0x6a, 0xfb, 0x61, 0xac, 0xa5,
                0xe7, 0x62
            ]
        );
        assert_eq!(
            *iv,
            [
                0x85, 0x71, 0x58, 0x76, 0x2f, 0x06, 0x7c, 0xaa, 0x15, 0x92, 0x9f, 0xa9, 0x31, 0x64,
                0x95
            ]
        );
    }
}
