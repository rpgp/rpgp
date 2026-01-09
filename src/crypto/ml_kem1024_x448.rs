use std::cmp::PartialEq;

use log::debug;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    KemCore, MlKem1024, MlKem1024Params,
};
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};
use x448::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, public_key::PublicKeyAlgorithm, Decryptor},
    errors::{ensure, Result},
    ser::Serialize,
    types::MlKem1024X448PublicParams,
};

/// Size in bytes of the X448 secret key.
pub const X448_KEY_LEN: usize = 56;
/// Size in bytes of the ML KEM 1024 secret key.
pub const ML_KEM1024_KEY_LEN: usize = 64;

/// Secret key for ML KEM 1024 X448
#[derive(Clone, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    x448: StaticSecret,
    #[debug("..")]
    ml_kem: Box<DecapsulationKey<MlKem1024Params>>,
    /// Seed `d` and `z`
    #[debug("..")]
    ml_kem_seed: Zeroizing<ml_kem::Seed>,
}

impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlKem1024X448PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            x448_key: PublicKey::from(&value.x448),
            ml_kem_key: Box::new(value.ml_kem.encapsulation_key().clone()),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.x448.as_bytes().eq(other.x448.as_bytes()) && self.ml_kem_seed.eq(&other.ml_kem_seed)
    }
}

impl Eq for SecretKey {}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let (a, b) = self.as_bytes();
        writer.write_all(a)?;
        writer.write_all(b)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        X448_KEY_LEN + ML_KEM1024_KEY_LEN
    }
}

impl SecretKey {
    /// Generate a `SecretKey`.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let x448 = StaticSecret::random_from_rng(rng);

        let mut seed = ml_kem::Seed::default();

        rng.fill_bytes(&mut seed);

        let (de, _) = MlKem1024::from_seed(seed);

        Self {
            x448,
            ml_kem: Box::new(de),
            ml_kem_seed: Zeroizing::new(seed),
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        x448: [u8; X448_KEY_LEN],
        ml_kem: [u8; ML_KEM1024_KEY_LEN],
    ) -> Result<Self> {
        let seed = ml_kem::Seed::from(ml_kem);

        let (ml_kem, _) = MlKem1024::from_seed(seed);

        let x = StaticSecret::from(x448);

        Ok(Self {
            x448: x,
            ml_kem: Box::new(ml_kem),
            ml_kem_seed: Zeroizing::new(seed),
        })
    }

    /// Returns the individual secret keys in their raw byte level representation.
    pub fn as_bytes(&self) -> (&[u8; X448_KEY_LEN], &[u8; ML_KEM1024_KEY_LEN]) {
        (self.x448.as_bytes(), self.ml_kem_seed.as_ref())
    }
}

pub struct EncryptionFields<'a> {
    /// Ephemeral X448 public key
    pub ecdh_ciphertext: &'a PublicKey,

    pub ml_kem_ciphertext: &'a [u8; 1568],

    /// Recipient public key
    pub ecdh_pub_key: &'a PublicKey,
    pub ml_kem_pub_key: &'a EncapsulationKey<MlKem1024Params>,

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        debug!("ML KEM 1024 X448 decrypt");

        // Compute (ecdhKeyShare) := ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey, ecdhPublicKey)
        let ecdh_key_share = x448_kem_decaps(data.ecdh_ciphertext, &self.x448, data.ecdh_pub_key);

        // Compute (mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)
        let ml_kem_key_share = ml_kem_1024_decaps(data.ml_kem_ciphertext, &self.ml_kem);
        // Compute KEK := multiKeyCombine(
        //                  mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
        //                  ecdhCipherText, ecdhPublicKey, algId
        //                )
        let kek = multi_key_combine(
            &ml_kem_key_share,
            &ecdh_key_share,
            data.ecdh_ciphertext,
            data.ecdh_pub_key,
            PublicKeyAlgorithm::MlKem1024X448,
        );
        // Compute sessionKey := AESKeyUnwrap(KEK, C) with AES-256 as per [RFC3394], aborting if the 64 bit integrity check fails
        // Output sessionKey
        let decrypted_key = aes_kw::unwrap(&kek, data.encrypted_session_key)?;
        ensure!(!decrypted_key.is_empty(), "empty key is not valid");

        Ok(decrypted_key)
    }
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-x448-kem>
fn x448_kem_decaps(
    their_public: &PublicKey,
    ecdh_secret_key: &StaticSecret,
    _ecdh_public_key: &PublicKey,
) -> [u8; 56] {
    // derive shared secret
    let shared_secret = ecdh_secret_key.diffie_hellman(their_public);

    *shared_secret.as_bytes()
}

fn ml_kem_1024_decaps(
    ml_kem_ciphertext: &[u8; 1568],
    ml_kem_secret_key: &DecapsulationKey<MlKem1024Params>,
) -> [u8; 32] {
    let shared = ml_kem_secret_key
        .decapsulate(ml_kem_ciphertext.into())
        .expect("infallible");
    shared.into()
}

const DOM_SEP: &[u8] = b"OpenPGPCompositeKDFv1";

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-key-combiner>
fn multi_key_combine(
    ml_kem_key_share: &[u8; 32],
    ecdh_key_share: &[u8; 56],
    ecdh_cipher_text: &PublicKey,
    ecdh_public_key: &PublicKey,
    alg: PublicKeyAlgorithm,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // SHA3-256(
    //           mlkemKeyShare || ecdhKeyShare ||
    //           ecdhCipherText || ecdhPublicKey ||
    //           algId || domSep || len(domSep)
    hasher.update(ml_kem_key_share);
    hasher.update(ecdh_key_share);
    hasher.update(ecdh_cipher_text.as_bytes());
    hasher.update(ecdh_public_key.as_bytes());
    hasher.update(&[u8::from(alg)][..]);
    hasher.update(DOM_SEP);
    hasher.update([u8::try_from(DOM_SEP.len()).expect("fixed size")]);

    hasher.finalize().into()
}

/// ML KEM 1024 - X448 Encryption
///
/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-encryption-procedure>
///
/// Returns
/// - ecdh_ciphertext
/// - ml_kem_ciphertext
/// - encrypted data
pub fn encrypt<R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    ecdh_public_key: &PublicKey,
    ml_kem_public_key: &EncapsulationKey<MlKem1024Params>,
    plain: &[u8],
) -> Result<(PublicKey, Box<[u8; 1568]>, Vec<u8>)> {
    // Maximum length for `plain` - FIXME: what should the maximum be, here?
    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    // Compute (ecdhCipherText, ecdhKeyShare) := ECDH-KEM.Encaps(ecdhPublicKey)
    let (ecdh_ciphertext, ecdh_key_share) = x448_kem_encaps(rng, ecdh_public_key);
    // Compute (mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)
    let (ml_kem_ciphertext, ml_kem_key_share) = ml_kem_encaps(rng, ml_kem_public_key);
    // Compute KEK := multiKeyCombine(mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
    //                        ecdhCipherText, ecdhPublicKey, algId, 256)

    let kek = multi_key_combine(
        &ml_kem_key_share,
        &ecdh_key_share,
        &ecdh_ciphertext,
        ecdh_public_key,
        PublicKeyAlgorithm::MlKem1024X448,
    );

    // Compute C := AESKeyWrap(KEK, sessionKey) with AES-256 as per [RFC3394] that includes a 64 bit integrity check
    let c = aes_kw::wrap(&kek, plain)?;

    Ok((ecdh_ciphertext, ml_kem_ciphertext, c))
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-x448-kem>
fn x448_kem_encaps<R: CryptoRng + ?Sized>(
    rng: &mut R,
    public_key: &PublicKey,
) -> (PublicKey, [u8; 56]) {
    // Generate an ephemeral key pair {v, V} via V = X448(v,U(P)) where v is a randomly generated octet string with a length of 56 octets
    let our_secret = StaticSecret::random_from_rng(rng);

    // Compute the shared coordinate X = X448(v, R) where R is the recipient's public key ecdhPublicKey
    let shared_secret = our_secret.diffie_hellman(public_key);

    let ephemeral_public = PublicKey::from(&our_secret);
    (ephemeral_public, *shared_secret.as_bytes())
}

fn ml_kem_encaps<R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    public_key: &EncapsulationKey<MlKem1024Params>,
) -> (Box<[u8; 1568]>, [u8; 32]) {
    let Ok((ciphertext, share)) = public_key.encapsulate_with_rng(rng);
    (Box::new(ciphertext.into()), share.into())
}

#[cfg(test)]
mod tests {
    use chacha20::{ChaCha20Rng, ChaCha8Rng};
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let skey = SecretKey::generate(&mut rng);
        let pub_params: MlKem1024X448PublicParams = (&skey).into();

        for text_size in (8..=248).step_by(8) {
            let mut plain = vec![0u8; text_size];
            rng.fill_bytes(&mut plain);

            let (ecdh_ciphertext, ml_kem_ciphertext, encrypted_session_key) = encrypt(
                &mut rng,
                &pub_params.x448_key,
                &pub_params.ml_kem_key,
                &plain[..],
            )
            .unwrap();

            let data = EncryptionFields {
                ecdh_ciphertext: &ecdh_ciphertext,
                ml_kem_ciphertext: &ml_kem_ciphertext,
                ecdh_pub_key: &pub_params.x448_key,
                ml_kem_pub_key: &pub_params.ml_kem_key,
                encrypted_session_key: &encrypted_session_key,
            };

            let decrypted = skey.decrypt(data).unwrap();

            assert_eq!(&plain[..], &decrypted[..]);
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
