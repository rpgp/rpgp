use std::cmp::PartialEq;

use cx448::x448::{PublicKey, Secret};
use log::debug;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, public_key::PublicKeyAlgorithm, Decryptor},
    errors::{ensure, Result},
    ser::Serialize,
    types::MlKem1024X448PublicParams,
};

/// Secret key for ML KEM 1024 X448
#[derive(Clone, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    pub(crate) x448: Secret,
    #[debug("..")]
    pub(crate) ml_kem: Box<DecapsulationKey<MlKem1024Params>>,
    /// Seed `d` and `z`
    #[debug("..")]
    pub(crate) ml_kem_seed: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
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
        writer.write_all(self.x448.as_bytes())?;
        writer.write_all(&self.ml_kem_seed.0[..])?;
        writer.write_all(&self.ml_kem_seed.1[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        56 + 64
    }
}

impl SecretKey {
    /// Generate a `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let x448 = Secret::new(&mut rng);

        let mut d = Zeroizing::new([0u8; 32]);
        let mut z = Zeroizing::new([0u8; 32]);

        rng.fill_bytes(&mut *d);
        rng.fill_bytes(&mut *z);

        let (de, _) = MlKem1024::generate_deterministic(&((*d).into()), &((*z).into()));

        Self {
            x448,
            ml_kem: Box::new(de),
            ml_kem_seed: (d, z),
        }
    }

    pub(crate) fn try_from_parts(x: Secret, ml_kem: [u8; 64]) -> Result<Self> {
        let d: Zeroizing<[u8; 32]> = Zeroizing::new(ml_kem[..32].try_into().expect("fixed size"));
        let z: Zeroizing<[u8; 32]> = Zeroizing::new(ml_kem[32..].try_into().expect("fixed size"));

        let (ml_kem, _) = MlKem1024::generate_deterministic(&((*d).into()), &((*z).into()));

        Ok(Self {
            x448: x,
            ml_kem: Box::new(ml_kem),
            ml_kem_seed: (d, z),
        })
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
            data.ml_kem_ciphertext,
            data.ml_kem_pub_key,
            &ecdh_key_share,
            data.ecdh_ciphertext,
            data.ecdh_pub_key,
            PublicKeyAlgorithm::MlKem1024X448Draft,
        );
        // Compute sessionKey := AESKeyUnwrap(KEK, C) with AES-256 as per [RFC3394], aborting if the 64 bit integrity check fails
        // Output sessionKey
        let decrypted_key = aes_kw::unwrap(&kek, data.encrypted_session_key)?;
        ensure!(!decrypted_key.is_empty(), "empty key is not valid");

        Ok(decrypted_key)
    }
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-x448-kem>
fn x448_kem_decaps(
    their_public: &PublicKey,
    ecdh_secret_key: &Secret,
    _ecdh_public_key: &PublicKey,
) -> [u8; 56] {
    // derive shared secret
    let shared_secret = ecdh_secret_key
        .as_diffie_hellman(their_public)
        .expect("point checked before");

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

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-key-combiner>
fn multi_key_combine(
    ml_kem_key_share: &[u8; 32],
    ml_kem_cipher_text: &[u8; 1568],
    ml_kem_public_key: &EncapsulationKey<MlKem1024Params>,
    ecdh_key_share: &[u8; 56],
    ecdh_cipher_text: &PublicKey,
    ecdh_public_key: &PublicKey,
    alg: PublicKeyAlgorithm,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // SHA3-256( mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey
    //             || mlkemCipherText || mlkemPublicKey || algId || domSep )
    hasher.update(ml_kem_key_share);
    hasher.update(ecdh_key_share);
    hasher.update(ecdh_cipher_text.as_bytes());
    hasher.update(ecdh_public_key.as_bytes());
    hasher.update(ml_kem_cipher_text);
    hasher.update(ml_kem_public_key.as_bytes());
    hasher.update(&[u8::from(alg)][..]);
    hasher.update(DOM_SEP);

    hasher.finalize().into()
}

/// ML KEM 1024 - X448 Encryption
///
/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-encryption-procedure>
///
/// Returns
/// - ecdh_ciphertext
/// - ml_kem_ciphertext
/// - encrpyted data
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
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
    let (ecdh_ciphertext, ecdh_key_share) = x448_kem_encaps(&mut rng, ecdh_public_key);
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
        PublicKeyAlgorithm::MlKem1024X448Draft,
    );

    // Compute C := AESKeyWrap(KEK, sessionKey) with AES-256 as per [RFC3394] that includes a 64 bit integrity check
    let c = aes_kw::wrap(&kek, plain)?;

    Ok((ecdh_ciphertext, ml_kem_ciphertext, c))
}

/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-07.html#name-x448-kem>
fn x448_kem_encaps<R: CryptoRng + Rng>(
    mut rng: R,
    public_key: &PublicKey,
) -> (PublicKey, [u8; 56]) {
    // Generate an ephemeral key pair {v, V} via V = X448(v,U(P)) where v is a randomly generated octet string with a length of 56 octets
    let our_secret = Secret::new(&mut rng);

    // Compute the shared coordinate X = X448(v, R) where R is the recipient's public key ecdhPublicKey
    let shared_secret = our_secret.as_diffie_hellman(public_key).expect("checked");

    let ephemeral_public = PublicKey::from(&our_secret);
    (ephemeral_public, *shared_secret.as_bytes())
}

fn ml_kem_encaps<R: CryptoRng + Rng>(
    mut rng: R,
    public_key: &EncapsulationKey<MlKem1024Params>,
) -> (Box<[u8; 1568]>, [u8; 32]) {
    let (ciphertext, share) = public_key.encapsulate(&mut rng).expect("infallible");
    (Box::new(ciphertext.into()), share.into())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::{ChaCha8Rng, ChaChaRng};

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::seed_from_u64(0);
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
