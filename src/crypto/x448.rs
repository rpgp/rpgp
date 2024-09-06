use hkdf::Hkdf;
use log::debug;
use rand::{CryptoRng, Rng};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{aes_kw, Decryptor, KeyParams};
use crate::errors::Result;
use crate::types::{PlainSecretParams, PublicParams};

/// Secret key for X448
#[derive(Clone, derive_more::Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[debug("..")]
    pub(crate) secret: [u8; 56],
}

impl KeyParams for SecretKey {
    type KeyParams = ();

    fn key_params(&self) {}
}

pub struct EncryptionFields<'a> {
    /// Ephemeral X448 public key (56 bytes)
    pub ephemeral_public_point: [u8; 56],

    /// Recipient public key (56 bytes)
    pub recipient_public: [u8; 56],

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        debug!("X448 decrypt");

        let shared_secret = {
            // create montgomery point
            let their_public =
                x448::PublicKey::from_bytes(&data.ephemeral_public_point).expect("56");

            // private key of the recipient.
            let our_secret = x448::Secret::from(self.secret);

            // derive shared secret (None for low order points)
            let Some(shared_secret) = our_secret.as_diffie_hellman(&their_public) else {
                bail!("x448 Secret::as_diffie_hellman returned None");
            };

            *shared_secret.as_bytes()
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
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
pub fn derive_session_key(
    ephemeral: [u8; 56],
    recipient_public: [u8; 56],
    shared_secret: [u8; 56],
    encrypted_session_key: &[u8],
) -> Result<Vec<u8>> {
    let okm = hkdf(&ephemeral, &recipient_public, &shared_secret)?;

    let decrypted_key = aes_kw::unwrap(&okm, encrypted_session_key)?;
    ensure!(!decrypted_key.is_empty(), "empty key is not valid");

    Ok(decrypted_key)
}

/// Generate an X448 KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(mut rng: R) -> (PublicParams, PlainSecretParams) {
    let mut secret_key_bytes = Zeroizing::new([0u8; 56]);
    rng.fill_bytes(&mut *secret_key_bytes);

    let secret = x448::Secret::from(*secret_key_bytes); // does clamping
    let public = *x448::PublicKey::from(&secret).as_bytes();

    (
        PublicParams::X448 { public },
        PlainSecretParams::X448(*secret.as_bytes()),
    )
}

/// HKDF for X448
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
pub fn hkdf(
    ephemeral: &[u8; 56],
    recipient_public: &[u8; 56],
    shared_secret: &[u8; 56],
) -> Result<[u8; 32]> {
    // TODO: maybe share/DRY this code with the analogous x25519 implementation?

    const INFO: &[u8] = b"OpenPGP X448";

    // The input of HKDF is the concatenation of the following three values:
    // 56 octets of the ephemeral X448 public key from this packet.
    // 56 octets of the recipient public key material.
    // 56 octets of the shared secret.

    let mut input = vec![];
    input.extend_from_slice(ephemeral);
    input.extend_from_slice(recipient_public);
    input.extend_from_slice(shared_secret);

    // HKDF with SHA512, an info parameter of "OpenPGP X448" and no salt.
    let hk = Hkdf::<Sha512>::new(None, &input);
    let mut okm = [0u8; 32];
    hk.expand(INFO, &mut okm)
        .expect("32 is a valid length for Sha512 to output");

    Ok(okm)
}

/// X448 encryption.
///
/// Returns (ephemeral, encrypted session key)
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    recipient_public: [u8; 56],
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
        let their_public = x448::PublicKey::from_bytes(&recipient_public).expect("56");

        let mut ephemeral_secret_key_bytes = Zeroizing::new([0u8; 56]);
        rng.fill_bytes(&mut *ephemeral_secret_key_bytes);
        let our_secret = x448::Secret::from(*ephemeral_secret_key_bytes);

        // derive shared secret (None for low order points)
        let Some(shared_secret) = our_secret.as_diffie_hellman(&their_public) else {
            bail!("x448 Secret::as_diffie_hellman returned None");
        };

        // Encode public point
        let ephemeral_public = x448::PublicKey::from(&our_secret);

        (ephemeral_public, shared_secret)
    };

    // hkdf key derivation
    let okm = hkdf(
        ephemeral_public.as_bytes(),
        &recipient_public,
        shared_secret.as_bytes(),
    )?;

    // Perform AES Key Wrap
    let wrapped = aes_kw::wrap(&okm, plain)?;

    Ok((*ephemeral_public.as_bytes(), wrapped))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ops::Deref;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::types::SecretKeyRepr;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let (pkey, skey) = generate_key(&mut rng);

        let PublicParams::X448 { public } = pkey else {
            panic!("invalid key generated")
        };
        let SecretKeyRepr::X448(ref secret) = skey.as_ref().as_repr(&pkey).unwrap() else {
            panic!("invalid key generated")
        };

        for text_size in (8..=248).step_by(8) {
            for _i in 0..10 {
                let mut fingerprint = vec![0u8; 20];
                rng.fill_bytes(&mut fingerprint);

                let mut plain = vec![0u8; text_size];
                rng.fill_bytes(&mut plain);

                let (ephemeral, enc_sk) = encrypt(&mut rng, public, &plain[..]).unwrap();

                let data = EncryptionFields {
                    ephemeral_public_point: ephemeral,
                    recipient_public: public,
                    encrypted_session_key: enc_sk.deref(),
                };

                let decrypted = secret.decrypt(data).unwrap();

                assert_eq!(&plain[..], &decrypted[..]);
            }
        }
    }
}
