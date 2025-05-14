use std::cmp::PartialEq;

use hkdf::Hkdf;
use log::debug;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, Decryptor},
    errors::{ensure, Result},
    ser::Serialize,
    types::X25519PublicParams,
};

pub const KEY_LEN: usize = 32;

/// Secret key for X25519
#[derive(Clone, derive_more::Debug, ZeroizeOnDrop)]
pub struct SecretKey {
    #[debug("..")]
    secret: StaticSecret,
}

impl From<&SecretKey> for X25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: PublicKey::from(&value.secret),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.secret.as_bytes().eq(other.secret.as_bytes())
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    /// Generate an X25519 `SecretKey`.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut secret_key_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *secret_key_bytes);

        let secret = StaticSecret::from(*secret_key_bytes);
        SecretKey { secret }
    }

    pub fn try_from_bytes(secret: [u8; KEY_LEN]) -> Result<Self> {
        let secret = x25519_dalek::StaticSecret::from(secret);
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
    /// Ephemeral X25519 public key (32 bytes)
    pub ephemeral_public_point: [u8; 32],

    /// Recipient public key (32 bytes)
    pub recipient_public: [u8; 32],

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        debug!("X25519 decrypt");

        let shared_secret = {
            // create montgomery point
            let their_public = x25519_dalek::PublicKey::from(data.ephemeral_public_point);

            // private key of the recipient.
            let our_secret = &self.secret;

            // derive shared secret
            let shared_secret = our_secret.diffie_hellman(&their_public);

            shared_secret.to_bytes()
        };

        // obtain the session key from the shared secret
        derive_session_key(
            data.ephemeral_public_point,
            data.recipient_public,
            shared_secret,
            data.encrypted_session_key,
        )
    }
}

/// Obtain the decrypted OpenPGP session key
///
/// This helper function performs the steps described in
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for->
pub fn derive_session_key(
    ephemeral: [u8; 32],
    recipient_public: [u8; 32],
    shared_secret: [u8; 32],
    encrypted_session_key: &[u8],
) -> Result<Vec<u8>> {
    let okm = hkdf(&ephemeral, &recipient_public, &shared_secret)?;

    let decrypted_key = aes_kw::unwrap(&okm, encrypted_session_key)?;
    ensure!(!decrypted_key.is_empty(), "empty key is not valid");

    Ok(decrypted_key)
}

/// HKDF for X25519
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for->
pub fn hkdf(
    ephemeral: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<[u8; 16]> {
    const INFO: &[u8] = b"OpenPGP X25519";

    // The input of HKDF is the concatenation of the following three values:
    // 32 octets of the ephemeral X25519 public key from this packet.
    // 32 octets of the recipient public key material.
    // 32 octets of the shared secret.

    let mut input = vec![];
    input.extend_from_slice(ephemeral);
    input.extend_from_slice(recipient_public);
    input.extend_from_slice(shared_secret);

    // HKDF with SHA256, an info parameter of "OpenPGP X25519" and no salt.
    let hk = Hkdf::<Sha256>::new(None, &input);
    let mut okm = [0u8; 16];
    hk.expand(INFO, &mut okm)
        .expect("16 is a valid length for Sha256 to output");

    Ok(okm)
}

/// X25519 encryption.
///
/// Returns (ephemeral, encrypted session key)
pub fn encrypt<R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    recipient_public: &x25519_dalek::PublicKey,
    plain: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    debug!("X25519 encrypt");

    // Maximum length for `plain` - FIXME: what should the maximum be, here?
    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (ephemeral_public, shared_secret) = {
        let mut ephemeral_secret_key_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *ephemeral_secret_key_bytes);
        let our_secret = StaticSecret::from(*ephemeral_secret_key_bytes);

        // derive shared secret
        let shared_secret = our_secret.diffie_hellman(recipient_public);

        // Encode public point
        let ephemeral_public = x25519_dalek::PublicKey::from(&our_secret);

        (ephemeral_public, shared_secret)
    };

    // hkdf key derivation
    let okm = hkdf(
        ephemeral_public.as_bytes(),
        recipient_public.as_bytes(),
        shared_secret.as_bytes(),
    )?;

    // Perform AES Key Wrap
    let wrapped = aes_kw::wrap(&okm, plain)?;

    Ok((ephemeral_public.to_bytes(), wrapped))
}

#[cfg(test)]
mod tests {
    use chacha20::ChaCha20Rng;
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn x25519_hkdf() {
        // A.8.2. X25519 encryption/decryption of the session key

        // Ephemeral key:
        let ephemeral_key = "87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764";
        let ephemeral_key: [u8; 32] = hex::decode(ephemeral_key).unwrap().try_into().unwrap();

        // This ephemeral key is derived from the following ephemeral secret key material, which is never placed on the wire:
        let _ephemeral_secret = "af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779";

        // Public key from target certificate (see Appendix A.3):
        let public_key = "8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435";
        let public_key: [u8; 32] = hex::decode(public_key).unwrap().try_into().unwrap();

        // The corresponding long-lived X25519 private key material (see Appendix A.4):
        let long_lived_private = "4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8";
        let long_lived_private: [u8; 32] =
            hex::decode(long_lived_private).unwrap().try_into().unwrap();

        // Shared point:
        let shared_point = "67e30e69cdc7bab2a2680d78aca46a2f8b6e2ae44d398bdc6f92c5ad4a492514";
        let shared_point: [u8; 32] = hex::decode(shared_point).unwrap().try_into().unwrap();

        // HKDF output:
        let hkdf = "f66dadcff64592239b254539b64ff607";
        let hkdf: [u8; 16] = hex::decode(hkdf).unwrap().try_into().unwrap();

        // Decrypted session key:
        let decrypted = "dd708f6fa1ed65114d68d2343e7c2f1d";
        let decrypted: [u8; 16] = hex::decode(decrypted).unwrap().try_into().unwrap();

        let esk = "dea355437956617901e06957fbca8a6a47a5b5153e8d3ab7";
        let esk = hex::decode(esk).unwrap();

        // ---

        // test hkdf helper
        let okm = super::hkdf(&ephemeral_key, &public_key, &shared_point).unwrap();
        assert_eq!(okm, hkdf);

        let decrypted_key = aes_kw::unwrap(&okm, &esk).unwrap();
        assert_eq!(decrypted_key, decrypted);

        // test SecretKey::decrypt
        let sk = SecretKey {
            secret: long_lived_private.into(),
        };
        let decrypted2 = sk
            .decrypt(EncryptionFields {
                ephemeral_public_point: ephemeral_key,
                recipient_public: public_key,
                encrypted_session_key: &esk,
            })
            .unwrap();

        assert_eq!(decrypted_key, decrypted2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let skey = SecretKey::generate(&mut rng);
        let pub_params: X25519PublicParams = (&skey).into();

        for text_size in (8..=248).step_by(8) {
            for _i in 0..10 {
                let mut plain = vec![0u8; text_size];
                rng.fill_bytes(&mut plain);

                let (ephemeral, enc_sk) = encrypt(&mut rng, &pub_params.key, &plain[..]).unwrap();

                let data = EncryptionFields {
                    ephemeral_public_point: ephemeral,
                    recipient_public: pub_params.key.to_bytes(),
                    encrypted_session_key: &enc_sk,
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
            any::<[u8; 32]>()
                .prop_map(|b| SecretKey {
                    secret: StaticSecret::from(b),
                })
                .boxed()
        }
    }
}
