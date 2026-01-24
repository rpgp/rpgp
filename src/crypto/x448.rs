use hkdf::HkdfExtract;
use log::debug;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, Decryptor},
    errors::{bail, ensure, Result},
    ser::Serialize,
    types::X448PublicParams,
};

pub const KEY_LEN: usize = 56;

/// Secret key for X448
#[derive(Clone, derive_more::Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[debug("..")]
    secret: x448::StaticSecret,
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.secret.as_bytes().eq(other.secret.as_bytes())
    }
}

impl Eq for SecretKey {}

impl From<&SecretKey> for X448PublicParams {
    fn from(value: &SecretKey) -> Self {
        let secret = &value.secret;
        let public = x448::PublicKey::from(secret);
        X448PublicParams { key: public }
    }
}

impl SecretKey {
    /// Generate an X448 `SecretKey`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let secret = x448::StaticSecret::random_from_rng(rng);

        SecretKey { secret }
    }

    pub fn try_from_bytes(secret: [u8; KEY_LEN]) -> Result<Self> {
        let secret = x448::StaticSecret::from(secret);

        Ok(Self { secret })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.secret.as_bytes()
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let x = self.as_bytes();
        writer.write_all(x)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        KEY_LEN
    }
}

pub struct EncryptionFields<'a> {
    /// Ephemeral X448 public key (56 bytes)
    pub ephemeral_public_point: [u8; 56],

    /// Recipient public key (56 bytes)
    pub recipient_public: &'a x448::PublicKey,

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        debug!("X448 decrypt");

        let shared_secret = {
            // create montgomery point
            let Some(their_public) = x448::PublicKey::from_bytes(&data.ephemeral_public_point)
            else {
                bail!("x448: invalid public key");
            };

            // private key of the recipient.
            let our_secret = &self.secret;

            let shared_secret = our_secret.diffie_hellman(&their_public);

            *shared_secret.as_bytes()
        };

        // obtain the session key from the shared secret
        derive_session_key(
            data.ephemeral_public_point,
            data.recipient_public.as_bytes(),
            shared_secret,
            data.encrypted_session_key,
        )
    }
}

/// Obtain the decrypted OpenPGP session key
///
/// This helper function performs the steps described in
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x>
pub fn derive_session_key(
    ephemeral: [u8; 56],
    recipient_public: &[u8; 56],
    shared_secret: [u8; 56],
    encrypted_session_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let okm = hkdf(&ephemeral, recipient_public, &shared_secret)?;

    let decrypted_key = aes_kw::unwrap(&*okm, encrypted_session_key)?;
    ensure!(!decrypted_key.is_empty(), "empty key is not valid");

    Ok(decrypted_key)
}

/// HKDF for X448
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x>
pub fn hkdf(
    ephemeral: &[u8; 56],
    recipient_public: &[u8; 56],
    shared_secret: &[u8; 56],
) -> Result<Zeroizing<[u8; 32]>> {
    // TODO: maybe share/DRY this code with the analogous x25519 implementation?

    const INFO: &[u8] = b"OpenPGP X448";

    // The input of HKDF is the concatenation of the following three values:
    // 56 octets of the ephemeral X448 public key from this packet.
    // 56 octets of the recipient public key material.
    // 56 octets of the shared secret.

    let mut hkdf_extract = HkdfExtract::<Sha512>::new(None);
    hkdf_extract.input_ikm(ephemeral);
    hkdf_extract.input_ikm(recipient_public);
    hkdf_extract.input_ikm(shared_secret);

    let (_, hkdf) = hkdf_extract.finalize();

    // HKDF with SHA512, an info parameter of "OpenPGP X448" and no salt.
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(INFO, &mut (*okm))
        .expect("32 is a valid length for Sha512 to output");

    Ok(okm)
}

/// X448 encryption.
///
/// Returns (ephemeral, encrypted session key)
pub fn encrypt<R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    recipient_public: &X448PublicParams,
    plain: &[u8],
) -> Result<([u8; 56], Vec<u8>)> {
    debug!("X448 encrypt");

    // Maximum length for `plain` - FIXME: what should the maximum be, here?
    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (ephemeral_public, shared_secret) = {
        // create montgomery point
        let their_public = &recipient_public.key;

        let mut ephemeral_secret_key_bytes = Zeroizing::new([0u8; 56]);
        rng.fill_bytes(&mut *ephemeral_secret_key_bytes);
        let our_secret = x448::StaticSecret::from(*ephemeral_secret_key_bytes);

        let shared_secret = our_secret.diffie_hellman(their_public);

        // Encode public point
        let ephemeral_public = x448::PublicKey::from(&our_secret);

        (ephemeral_public, shared_secret)
    };

    // hkdf key derivation
    let okm = hkdf(
        ephemeral_public.as_bytes(),
        recipient_public.key.as_bytes(),
        shared_secret.as_bytes(),
    )?;

    // Perform AES Key Wrap
    let wrapped = aes_kw::wrap(&*okm, plain)?;

    Ok((*ephemeral_public.as_bytes(), wrapped))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ops::Deref;

    use chacha20::{ChaCha20Rng, ChaCha8Rng};
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let skey = SecretKey::generate(&mut rng);
        let pub_params: X448PublicParams = (&skey).into();

        for text_size in (8..=248).step_by(8) {
            for _i in 0..10 {
                let mut fingerprint = vec![0u8; 20];
                rng.fill_bytes(&mut fingerprint);

                let mut plain = vec![0u8; text_size];
                rng.fill_bytes(&mut plain);

                let (ephemeral, enc_sk) = encrypt(&mut rng, &pub_params, &plain[..]).unwrap();

                let data = EncryptionFields {
                    ephemeral_public_point: ephemeral,
                    recipient_public: &pub_params.key,
                    encrypted_session_key: enc_sk.deref(),
                };

                let decrypted = skey.decrypt(data).unwrap();

                assert_eq!(&plain[..], &decrypted[..]);
            }
        }
    }

    impl Arbitrary for SecretKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u64>()
                .prop_map(|seed| {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed);
                    SecretKey::generate(&mut rng)
                })
                .boxed()
        }
    }
}
