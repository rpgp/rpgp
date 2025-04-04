use std::cmp::PartialEq;

use log::debug;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, public_key::PublicKeyAlgorithm, Decryptor},
    errors::{ensure, Result},
    types::MlKem768X25519PublicParams,
};

/// Secret key for ML KEM 768 X25519
#[derive(Clone, derive_more::Debug, ZeroizeOnDrop)]
pub struct SecretKey {
    #[debug("..")]
    pub(crate) x25519: StaticSecret,
    #[debug("..")]
    pub(crate) ml_kem: DecapsulationKey<MlKem768Params>,
}

impl From<&SecretKey> for MlKem768X25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            x25519_key: PublicKey::from(&value.x25519),
            ml_kem_key: value.ml_kem.encapsulation_key(),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.x25519.as_bytes().eq(other.x25519.as_bytes()) && self.ml_kem.eq(&other.ml_kem)
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    /// Generate a `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let mut secret_key_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *secret_key_bytes);

        let x25519 = StaticSecret::from(*secret_key_bytes);

        let (de, _) = MlKem768::generate(&mut rng);
        Self { x25519, ml_kem: de }
    }

    pub(crate) fn try_from_parts(x: StaticSecret, ml_kem: [u8; 64]) -> Result<Self> {
        let ml_kem = DecapsulationKey::from_bytes(&(ml_kem.into()));

        Ok(Self { x25519: x, ml_kem })
    }
}

pub struct EncryptionFields<'a> {
    /// Ephemeral X25519 public key (32 bytes)
    pub ecdh_ciphertext: [u8; 32],

    pub ml_kem_ciphertext: &'a [u8; 1088],

    /// Recipient public key (32 bytes)
    pub ecdh_pub_key: &'a x25519_dalek::PublicKey,
    pub ml_kem_pub_key: &'a EncapsulationKey<MlKem768Params>,

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        debug!("ML KEM 768 X25519 decrypt");

        // Compute (ecdhKeyShare) := ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey, ecdhPublicKey)
        let ecdh_key_share =
            x25519_kem_decaps(&data.ecdh_ciphertext, &self.x25519, &data.ecdh_pub_key);

        // Compute (mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)
        let ml_kem_key_share = ml_kem_768_decaps(&data.ml_kem_ciphertext, &self.ml_kem);
        // Compute KEK := multiKeyCombine(
        //                  mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
        //                  ecdhCipherText, ecdhPublicKey, algId
        //                )
        let kek = multi_key_combine(
            &ml_kem_key_share,
            &data.ml_kem_ciphertext,
            &data.ml_kem_pub_key,
            &ecdh_key_share,
            &data.ecdh_ciphertext,
            &data.ecdh_pub_key,
            PublicKeyAlgorithm::MlKem768X25519Draft,
        );
        // Compute sessionKey := AESKeyUnwrap(KEK, C) with AES-256 as per [RFC3394], aborting if the 64 bit integrity check fails
        // Output sessionKey
        let decrypted_key = aes_kw::unwrap(&kek, data.encrypted_session_key)?;
        ensure!(!decrypted_key.is_empty(), "empty key is not valid");

        Ok(decrypted_key)
    }
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-x25519-kem>
fn x25519_kem_decaps(
    ecdh_ciphertext: &[u8; 32],
    ecdh_secret_key: &x25519_dalek::StaticSecret,
    _ecdh_public_key: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    // create montgomery point
    let their_public = x25519_dalek::PublicKey::from(*ecdh_ciphertext);

    // derive shared secret
    let shared_secret = ecdh_secret_key.diffie_hellman(&their_public);

    shared_secret.to_bytes()
}

fn ml_kem_768_decaps(
    ml_kem_ciphertext: &[u8; 1088],
    ml_kem_secret_key: &DecapsulationKey<MlKem768Params>,
) -> [u8; 32] {
    let shared = ml_kem_secret_key
        .decapsulate(ml_kem_ciphertext.into())
        .expect("infallible");
    shared.into()
}

const DOM_SEP: &[u8] = b"OpenPGPCompositeKDFv1";

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-key-combiner>
fn multi_key_combine(
    ml_kem_key_share: &[u8; 32],
    ml_kem_cipher_text: &[u8; 1088],
    ml_kem_public_key: &EncapsulationKey<MlKem768Params>,
    ecdh_key_share: &[u8; 32],
    ecdh_cipher_text: &[u8; 32],
    ecdh_public_key: &x25519_dalek::PublicKey,
    alg: PublicKeyAlgorithm,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // SHA3-256( mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey
    //             || mlkemCipherText || mlkemPublicKey || algId || domSep )
    hasher.update(ml_kem_key_share);
    hasher.update(ecdh_key_share);
    hasher.update(ecdh_cipher_text);
    hasher.update(ecdh_public_key);
    hasher.update(ml_kem_cipher_text);
    hasher.update(ml_kem_public_key.as_bytes());
    hasher.update(&[u8::from(alg)][..]);
    hasher.update(DOM_SEP);

    hasher.finalize().into()
}

/// ML KEM 768 - X25519 Encryption
///
/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-encryption-procedure>
///
/// Returns
/// - ecdh_ciphertext
/// - ml_kem_ciphertext
/// - encrpyted data
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    ecdh_public_key: &x25519_dalek::PublicKey,
    ml_kem_public_key: &EncapsulationKey<MlKem768Params>,
    plain: &[u8],
) -> Result<([u8; 32], [u8; 1088], Vec<u8>)> {
    // Maximum length for `plain` - FIXME: what should the maximum be, here?
    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    // Compute (ecdhCipherText, ecdhKeyShare) := ECDH-KEM.Encaps(ecdhPublicKey)
    let (ecdh_ciphertext, ecdh_key_share) = x25519_kem_encaps(&mut rng, ecdh_public_key);
    // Compute (mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)
    let (ml_kem_ciphertext, ml_kem_key_share) = ml_kem_encaps(&mut rng, ml_kem_public_key);
    // Compute KEK := multiKeyCombine(mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
    //                        ecdhCipherText, ecdhPublicKey, algId, 256)

    let kek = multi_key_combine(
        &ml_kem_key_share,
        &ml_kem_ciphertext,
        ml_kem_public_key,
        &ecdh_key_share,
        &ecdh_ciphertext,
        ecdh_public_key,
        PublicKeyAlgorithm::MlKem768X25519Draft,
    );
    // Compute C := AESKeyWrap(KEK, sessionKey) with AES-256 as per [RFC3394] that includes a 64 bit integrity check
    let c = aes_kw::wrap(&kek, plain)?;

    Ok((ecdh_ciphertext, ml_kem_ciphertext, c))
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-x25519-kem>
fn x25519_kem_encaps<R: CryptoRng + Rng>(
    mut rng: R,
    public_key: &x25519_dalek::PublicKey,
) -> ([u8; 32], [u8; 32]) {
    // Generate an ephemeral key pair {v, V} via V = X25519(v,U(P)) where v is a randomly generated octet string with a length of 32 octets
    let mut ephemeral_secret_key_bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ephemeral_secret_key_bytes);
    let our_secret = StaticSecret::from(*ephemeral_secret_key_bytes);

    // Compute the shared coordinate X = X25519(v, R) where R is the recipient's public key ecdhPublicKey
    let shared_secret = our_secret.diffie_hellman(public_key);

    let ephemeral_public = x25519_dalek::PublicKey::from(&our_secret);
    (ephemeral_public.to_bytes(), shared_secret.to_bytes())
}

fn ml_kem_encaps<R: CryptoRng + Rng>(
    mut rng: R,
    public_key: &EncapsulationKey<MlKem768Params>,
) -> ([u8; 1088], [u8; 32]) {
    let (ciphertext, share) = public_key.encapsulate(&mut rng).expect("infallible");
    (ciphertext.into(), share.into())
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::seed_from_u64(0);
        let skey = SecretKey::generate(&mut rng);
        let pub_params: MlKem768X25519PublicParams = (&skey).into();

        for text_size in (8..=248).step_by(8) {
            let mut plain = vec![0u8; text_size];
            rng.fill_bytes(&mut plain);

            let (ecdh_ciphertext, ml_kem_ciphertext, encrypted_session_key) = encrypt(
                &mut rng,
                &pub_params.x25519_key,
                &pub_params.ml_kem_key,
                &plain[..],
            )
            .unwrap();

            let data = EncryptionFields {
                ecdh_ciphertext,
                ml_kem_ciphertext: &ml_kem_ciphertext,
                ecdh_pub_key: &pub_params.x25519_key,
                ml_kem_pub_key: &pub_params.ml_kem_key,
                encrypted_session_key: &encrypted_session_key,
            };

            let decrypted = skey.decrypt(data).unwrap();

            assert_eq!(&plain[..], &decrypted[..]);
        }
    }
}
