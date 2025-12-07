//! Persistent Symmetric Key support
//!
//! <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-algorithm-specific-fields-f>

use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{aead::AeadAlgorithm, sym::SymmetricKeyAlgorithm, Decryptor, HashAlgorithm, Signer},
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
    pub(crate) key: Box<[u8]>, // sized to match the sym_alg

    pub(crate) sym_alg: SymmetricKeyAlgorithm, // (copy of the information from the public part)
}

pub struct EncryptionFields<'a> {
    pub data: &'a Bytes,
    pub aead: AeadAlgorithm,
    pub version: PkeskVersion,
    pub salt: &'a [u8; 32],
}

pub(crate) struct InfoParameter {
    pub tag: Tag,
    pub version: u8,
    pub aead: AeadAlgorithm,
    pub sym_alg: SymmetricKeyAlgorithm,
}

impl From<InfoParameter> for [u8; 4] {
    fn from(value: InfoParameter) -> Self {
        [
            value.tag.encode(),
            value.version,
            value.aead.into(),
            value.sym_alg.into(),
        ]
    }
}

impl SecretKey {
    pub(crate) fn calculate_signature(
        &self,
        aead: AeadAlgorithm,
        version: SignatureVersion,
        salt: &[u8; 32],
        digest: &[u8],
    ) -> Result<BytesMut> {
        let info = InfoParameter {
            tag: Tag::Signature,
            version: version.into(),
            aead,
            sym_alg: self.sym_alg,
        };

        let (key, iv) = Self::derive(&self.key, salt, info);

        // An authentication tag of the size specified by the AEAD mode, created by encrypting the
        // empty value with the message authentication key and IV computed as described in Section
        // 7.4, using the symmetric-key cipher of the key and the indicated AEAD mode, with as
        // additional data the hash digest described in section 5.2.4 of [RFC9580].

        let mut buf = BytesMut::with_capacity(64);
        aead.encrypt_in_place(&self.sym_alg, &key, &iv, digest, &mut buf)?;
        Ok(buf)
    }

    /// Key and IV derivation
    /// <https://twisstle.gitlab.io/openpgp-persistent-symmetric-keys/#name-key-and-iv-derivation>
    ///
    /// Returns:
    /// - M bits of key, matching the size of SymmetricKeyAlgorithm,
    /// - N bit of IV, matching the nonce size of AeadAlgorithm
    pub(crate) fn derive(
        persistent_key: &[u8],
        salt: &[u8; 32],
        info: InfoParameter,
    ) -> (Vec<u8>, Vec<u8>) {
        let hk = Hkdf::<Sha256>::new(Some(salt), persistent_key);

        let key_size = info.sym_alg.key_size();
        let nonce_size = info.aead.nonce_size();

        // M + N bits are derived using HKDF.
        // The left-most M bits are used as symmetric algorithm key, the remaining N bits are
        // used as initialization vector.
        let info_parameter: [u8; 4] = info.into();

        // FIXME: zeroize
        let mut output = vec![0u8; key_size + nonce_size];
        hk.expand(&info_parameter, &mut output)
            .expect("expand size is < 255 * HashLength");

        let key = output[0..key_size].to_vec();
        let iv = output[key_size..].to_vec();

        (key, iv)
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        let Some(digest_size) = hash.digest_size() else {
            bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
        };
        ensure_eq!(
            digest.len(),
            digest_size,
            "Unexpected digest length {} for hash algorithm {:?}",
            digest.len(),
            hash,
        );

        // The signature consists of this series of values:
        //
        // A 1-octet AEAD algorithm (see section 9.6 of [RFC9580]).
        let aead = AeadAlgorithm::Ocb; // FIXME: should be a parameter

        // 32 octets of salt.
        // The salt is used to derive the message authentication key and MUST be securely generated
        // (see section 13.10 of [RFC9580]).
        let mut rng = thread_rng(); // FIXME: should be a parameter
        let mut salt: [u8; 32] = [0; 32];
        rng.fill(&mut salt);

        let version = SignatureVersion::V6; // FIXME: should be a parameter

        let buf = self.calculate_signature(aead, version, &salt, digest)?;

        Ok(SignatureBytes::PersistentSymmetric(aead, salt, buf.into()))
    }
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        let info = InfoParameter {
            tag: Tag::PublicKeyEncryptedSessionKey,
            version: data.version.into(),
            aead: data.aead,
            sym_alg: self.sym_alg,
        };

        let (key, iv) = Self::derive(&self.key, data.salt, info);

        let mut buf = data.data.clone().into(); // FIXME: don't clone

        data.aead
            .decrypt_in_place(&self.sym_alg, &key, &iv, &[], &mut buf)?;

        Ok(buf.into())
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
            let mut key :Box<[u8]>  = vec![0u8 ;32].into(); // FIXME: size depends on sym alg!

            rng.fill(&mut key[..]);

            key
        }
    }

    /// Key/IV derivation
    ///
    /// - persistent key: 16 bytes of 0x00
    /// - salt: 32 bytes of 0xff
    /// - info: Signature, Version 6, OCB, AES128
    ///
    /// output:
    /// - key: [e9, de, 26, 72, 2c, fb, 71, 2b, bf, 01, 15, a6, 06, 08, 08, b0]
    /// - iv: [dc, 1f, 35, cc, 3c, 28, 74, 0f, f4, 37, 09, 9e, ad, c0, 17]
    #[test]
    fn psk_derive() {
        let (key, iv) = SecretKey::derive(
            &[0; 16],
            &[0xff; 32],
            InfoParameter {
                tag: Tag::Signature,
                version: 6,
                aead: AeadAlgorithm::Ocb,
                sym_alg: SymmetricKeyAlgorithm::AES128,
            },
        );

        assert_eq!(
            &key,
            &[
                0xe9, 0xde, 0x26, 0x72, 0x2c, 0xfb, 0x71, 0x2b, 0xbf, 0x01, 0x15, 0xa6, 0x06, 0x08,
                0x08, 0xb0
            ]
        );
        assert_eq!(
            &iv,
            &[
                0xdc, 0x1f, 0x35, 0xcc, 0x3c, 0x28, 0x74, 0x0f, 0xf4, 0x37, 0x09, 0x9e, 0xad, 0xc0,
                0x17
            ]
        );
    }
}
