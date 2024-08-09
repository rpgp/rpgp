use std::fmt;

use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{Decryptor, KeyParams};
use crate::errors::Result;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

/// Secret key for X25519
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) secret: [u8; 32],
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519SecretKey")
            .field("secret", &"[..]")
            .finish()
    }
}

impl KeyParams for SecretKey {
    type KeyParams = ();

    fn key_params(&self) {}
}

impl Decryptor for SecretKey {
    // - Ephemeral X25519 public key (32 bytes).
    // - Recipient public key (32 bytes). [FIXME: use PublicParams and expect PublicParams::X25519?]
    // - Encrypted and wrapped session key.

    fn decrypt(&self, _mpis: &[Mpi], _fingerprint: &[u8]) -> Result<Vec<u8>> {
        unimplemented_err!("decrypt for x25519")
    }
}

/// Generate an X25519 KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(mut rng: R) -> (PublicParams, PlainSecretParams) {
    let mut secret_key_bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *secret_key_bytes);

    let secret = StaticSecret::from(*secret_key_bytes);
    let public = PublicKey::from(&secret).to_bytes();

    // secret key
    // FIXME: is clamping needed here?
    let q_raw = curve25519_dalek::scalar::clamp_integer(secret.to_bytes());

    (
        PublicParams::X25519 { public },
        PlainSecretParams::X25519(q_raw),
    )
}
