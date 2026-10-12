use std::cmp::PartialEq;

use generic_array::GenericArray;
use log::debug;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    KemCore, MlKem1024, MlKem1024Params,
};
use p521::NistP521;
use rand::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, public_key::PublicKeyAlgorithm, Decryptor},
    errors::{ensure, Result},
    ser::Serialize,
    types::MlKem1024NistP521PublicParams,
};

/// Size in bytes of the NIST P521 secret key.
pub const NISTP521_KEY_LEN: usize = 66;
/// Size in bytes of the ML KEM 1024 secret key.
pub const ML_KEM1024_KEY_LEN: usize = 64;

/// Secret key for ML KEM 1024 NIST P521
#[derive(Clone, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    nistp521: p521::SecretKey,
    #[debug("..")]
    ml_kem: Box<DecapsulationKey<MlKem1024Params>>,
    /// Seed `d` and `z`
    #[debug("..")]
    ml_kem_seed: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
}
impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlKem1024NistP521PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            nistp521_key: value.nistp521.public_key(),
            ml_kem_key: Box::new(value.ml_kem.encapsulation_key().clone()),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.nistp521.eq(&other.nistp521) && self.ml_kem_seed.eq(&other.ml_kem_seed)
    }
}

impl Eq for SecretKey {}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.nistp521.to_bytes())?;
        writer.write_all(&*self.ml_kem_seed.0)?;
        writer.write_all(&*self.ml_kem_seed.1)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        NISTP521_KEY_LEN + ML_KEM1024_KEY_LEN
    }
}

impl SecretKey {
    /// Generate a `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let nistp521 = p521::SecretKey::random(&mut rng);

        let mut d = Zeroizing::new([0u8; 32]);
        let mut z = Zeroizing::new([0u8; 32]);

        rng.fill_bytes(&mut *d);
        rng.fill_bytes(&mut *z);

        let (de, _) = MlKem1024::generate_deterministic(&((*d).into()), &((*z).into()));
        Self {
            nistp521,
            ml_kem: Box::new(de),
            ml_kem_seed: (d, z),
        }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        nistp521: [u8; NISTP521_KEY_LEN],
        ml_kem: [u8; ML_KEM1024_KEY_LEN],
    ) -> Result<Self> {
        let d: Zeroizing<[u8; 32]> = Zeroizing::new(ml_kem[..32].try_into().expect("fixed size"));
        let z: Zeroizing<[u8; 32]> = Zeroizing::new(ml_kem[32..].try_into().expect("fixed size"));

        let (ml_kem, _) = MlKem1024::generate_deterministic(&((*d).into()), &((*z).into()));

        let array = GenericArray::from_slice(&nistp521);
        let secret = elliptic_curve::SecretKey::<p521::NistP521>::from_bytes(array)?;

        Ok(Self {
            nistp521: secret,
            ml_kem: Box::new(ml_kem),
            ml_kem_seed: (d, z),
        })
    }
}

pub struct EncryptionFields<'a> {
    /// Ephemeral Nist P 521 public key (133 bytes)
    pub ecdh_ciphertext: [u8; 133],

    pub ml_kem_ciphertext: &'a [u8; 1568],

    /// Recipient public key (133 bytes)
    pub ecdh_pub_key: &'a p521::PublicKey,
    pub ml_kem_pub_key: &'a EncapsulationKey<MlKem1024Params>,

    /// Encrypted and wrapped session key
    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        debug!("ML KEM 1024 NIST P521 decrypt");

        // Compute (ecdhKeyShare) := ECDH-KEM.Decaps(ecdhCipherText, ecdhSecretKey, ecdhPublicKey)
        let ecdh_key_share =
            ecdh_kem_decaps(&data.ecdh_ciphertext, &self.nistp521, data.ecdh_pub_key)?;

        // Compute (mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)
        let ml_kem_key_share = ml_kem_1024_decaps(data.ml_kem_ciphertext, &self.ml_kem);
        // Compute KEK := multiKeyCombine(
        //                  mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
        //                  ecdhCipherText, ecdhPublicKey, algId
        //                )
        let kek = multi_key_combine(
            &ml_kem_key_share,
            &ecdh_key_share,
            &data.ecdh_ciphertext,
            data.ecdh_pub_key,
            PublicKeyAlgorithm::MlKem1024NistP521,
        );
        // Compute sessionKey := AESKeyUnwrap(KEK, C) with AES-256 as per [RFC3394], aborting if the 64 bit integrity check fails
        // Output sessionKey
        let decrypted_key = aes_kw::unwrap(&kek, data.encrypted_session_key)?;
        ensure!(!decrypted_key.is_empty(), "empty key is not valid");

        Ok(decrypted_key)
    }
}

fn ecdh_kem_decaps(
    ecdh_ciphertext: &[u8; 133],
    ecdh_secret_key: &p521::SecretKey,
    _ecdh_public_key: &p521::PublicKey,
) -> Result<[u8; 66]> {
    let ephemeral_public_key =
        elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(ecdh_ciphertext)?;

    // derive shared secret
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        ecdh_secret_key.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );

    Ok((*shared_secret.raw_secret_bytes())
        .to_vec()
        .try_into()
        .expect("66 bytes"))
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

/// <https://www.rfc-editor.org/info/rfc9980/#name-key-combiner>
fn multi_key_combine(
    ml_kem_key_share: &[u8; 32],
    ecdh_key_share: &[u8; 66],
    ecdh_cipher_text: &[u8; 133],
    ecdh_public_key: &p521::PublicKey,
    alg: PublicKeyAlgorithm,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // SHA3-256(
    //           mlkemKeyShare || ecdhKeyShare ||
    //           ecdhCipherText || ecdhPublicKey ||
    //           algId || domSep || len(domSep)
    hasher.update(ml_kem_key_share);
    hasher.update(ecdh_key_share);
    hasher.update(ecdh_cipher_text);
    hasher.update(ecdh_public_key.to_sec1_bytes());
    hasher.update(&[u8::from(alg)][..]);
    hasher.update(DOM_SEP);
    hasher.update([u8::try_from(DOM_SEP.len()).expect("fixed size")]);

    hasher.finalize().into()
}

/// ML KEM 1024 - NistP521 Encryption
///
/// <https://www.ietf.org/archive/id/draft-ietf-openpgp-nist-bp-comp-04.html#name-encryption-procedure>
///
/// Returns
/// - ecdh_ciphertext
/// - ml_kem_ciphertext
/// - encrypted data
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    ecdh_public_key: &p521::PublicKey,
    ml_kem_public_key: &EncapsulationKey<MlKem1024Params>,
    plain: &[u8],
) -> Result<([u8; 133], Box<[u8; 1568]>, Vec<u8>)> {
    // Maximum length for `plain` - FIXME: what should the maximum be, here?
    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    // Compute (ecdhCipherText, ecdhKeyShare) := ECDH-KEM.Encaps(ecdhPublicKey)
    let (ecdh_ciphertext, ecdh_key_share) = ecdh_kem_encaps(&mut rng, ecdh_public_key);

    // Compute (mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)
    let (ml_kem_ciphertext, ml_kem_key_share) = ml_kem_encaps(&mut rng, ml_kem_public_key);

    // Compute KEK := multiKeyCombine(mlkemKeyShare, mlkemCipherText, mlkemPublicKey, ecdhKeyShare,
    //                        ecdhCipherText, ecdhPublicKey, algId, 256)
    let kek = multi_key_combine(
        &ml_kem_key_share,
        &ecdh_key_share,
        &ecdh_ciphertext,
        ecdh_public_key,
        PublicKeyAlgorithm::MlKem1024NistP521,
    );

    // Compute C := AESKeyWrap(KEK, sessionKey) with AES-256 as per [RFC3394] that includes a 64 bit integrity check
    let c = aes_kw::wrap(&kek, plain)?;

    Ok((ecdh_ciphertext, ml_kem_ciphertext, c))
}

fn ecdh_kem_encaps<R: CryptoRng + Rng>(
    mut rng: R,
    public_key: &p521::PublicKey,
) -> ([u8; 133], [u8; 66]) {
    let our_secret = elliptic_curve::ecdh::EphemeralSecret::<NistP521>::random(&mut rng);

    let shared_secret = our_secret.diffie_hellman(public_key);

    let ephemeral_public = p521::PublicKey::from(&our_secret);
    let encoded = elliptic_curve::sec1::EncodedPoint::<NistP521>::from(ephemeral_public);

    (
        encoded.to_bytes().to_vec().try_into().expect("133 bytes"),
        (*shared_secret.raw_secret_bytes())
            .to_vec()
            .try_into()
            .expect("66 bytes"),
    )
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
        let pub_params: MlKem1024NistP521PublicParams = (&skey).into();

        for text_size in (8..=248).step_by(8) {
            let mut plain = vec![0u8; text_size];
            rng.fill_bytes(&mut plain);

            let (ecdh_ciphertext, ml_kem_ciphertext, encrypted_session_key) = encrypt(
                &mut rng,
                &pub_params.nistp521_key,
                &pub_params.ml_kem_key,
                &plain[..],
            )
            .unwrap();

            let data = EncryptionFields {
                ecdh_ciphertext,
                ml_kem_ciphertext: &ml_kem_ciphertext,
                ecdh_pub_key: &pub_params.nistp521_key,
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
