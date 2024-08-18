use log::debug;
use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::hash::HashAlgorithm;
use crate::crypto::{
    aes_kw, ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm,
    Decryptor, KeyParams,
};
use crate::errors::{Error, Result};
use crate::types::{Mpi, PlainSecretParams, PublicParams};
use crate::EskBytes;

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

/// Secret key for ECDH
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, derive_more::Debug)]
pub enum SecretKey {
    /// ECDH with Curve25519
    Curve25519 {
        /// The secret point.
        #[debug("..")]
        secret: [u8; ECCCurve::Curve25519.secret_key_length()],
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// ECDH with Nist P256
    P256 {
        /// The secret point.
        #[debug("..")]
        secret: [u8; ECCCurve::P256.secret_key_length()],
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// ECDH with Nist P384
    P384 {
        /// The secret point.
        #[debug("..")]
        secret: [u8; ECCCurve::P384.secret_key_length()],
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// ECDH with Nist P521
    P521 {
        /// The secret point.
        #[debug("..")]
        secret: [u8; ECCCurve::P521.secret_key_length()],
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
}

impl KeyParams for SecretKey {
    type KeyParams = (ECCCurve, SymmetricKeyAlgorithm, HashAlgorithm);

    fn key_params(&self) -> Self::KeyParams {
        match self {
            SecretKey::Curve25519 { hash, alg_sym, .. } => (ECCCurve::Curve25519, *alg_sym, *hash),
            SecretKey::P256 { hash, alg_sym, .. } => (ECCCurve::P256, *alg_sym, *hash),
            SecretKey::P384 { hash, alg_sym, .. } => (ECCCurve::P384, *alg_sym, *hash),
            SecretKey::P521 { hash, alg_sym, .. } => (ECCCurve::P521, *alg_sym, *hash),
        }
    }
}

impl Decryptor for SecretKey {
    type Data<'a> = (&'a Mpi, &'a [u8], &'a [u8]);

    fn decrypt(&self, data: Self::Data<'_>) -> Result<Vec<u8>> {
        let (
            public_point,
            encrypted_session_key, // encrypted and wrapped value derived from the session key
            fingerprint,
        ) = data;

        debug!("ECDH decrypt");

        let encrypted_key_len: usize = encrypted_session_key.len();

        let (curve, alg_sym, hash) = self.key_params();

        let shared_secret = match self {
            SecretKey::Curve25519 { secret, .. } => {
                ensure_eq!(
                    secret.len(),
                    curve.secret_key_length(),
                    "invalid secret point"
                );
                ensure_eq!(public_point.len(), 33, "invalid public point"); // prefix "0x40" + 32 bytes = 33 bytes

                let their_public = {
                    // public part of the ephemeral key (removes 0x40 prefix)
                    let ephemeral_public_key = &public_point.as_bytes()[1..];

                    // create montgomery point
                    let mut ephemeral_public_key_arr = [0u8; 32];
                    ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

                    x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
                };

                let our_secret = {
                    // private key of the recipient.
                    let private_key = &secret[..];

                    // create scalar and reverse to little endian
                    // https://www.rfc-editor.org/rfc/rfc9580.html#name-curve25519legacy-ecdh-secre
                    let mut private_key_le = private_key.iter().rev().cloned().collect::<Vec<u8>>();
                    let mut private_key_arr = [0u8; 32];
                    private_key_arr[..].copy_from_slice(&private_key_le);
                    private_key_le.zeroize();

                    StaticSecret::from(private_key_arr)
                };

                // derive shared secret
                let shared_secret = our_secret.diffie_hellman(&their_public);

                shared_secret.to_bytes().to_vec()
            }
            SecretKey::P256 { secret, .. } => {
                derive_shared_secret_decryption::<p256::NistP256>(public_point, secret, &curve, 65)?
            }
            SecretKey::P384 { secret, .. } => {
                derive_shared_secret_decryption::<p384::NistP384>(public_point, secret, &curve, 97)?
            }
            SecretKey::P521 { secret, .. } => derive_shared_secret_decryption::<p521::NistP521>(
                public_point,
                secret,
                &curve,
                133,
            )?,
        };

        // obtain the session key from the shared secret
        derive_session_key(
            &shared_secret,
            encrypted_session_key,
            encrypted_key_len,
            &(curve, alg_sym, hash),
            fingerprint,
        )
    }
}

/// Derive a shared secret in decryption, for a Rust Crypto curve
fn derive_shared_secret_decryption<C>(
    public_point: &Mpi,
    secret: &[u8],
    curve: &ECCCurve,
    pub_bytes: usize,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
{
    ensure_eq!(
        secret.len(),
        curve.secret_key_length(),
        "invalid secret point"
    );
    ensure_eq!(public_point.len(), pub_bytes, "invalid public point");

    let ephemeral_public_key =
        elliptic_curve::PublicKey::<C>::from_sec1_bytes(public_point.as_bytes())?;

    let our_secret = elliptic_curve::SecretKey::<C>::from_bytes(secret.into())?;

    // derive shared secret
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        our_secret.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Obtain the OpenPGP session key for a DH shared secret.
///
/// This helper function performs the key derivation and unwrapping steps
/// described in <https://www.rfc-editor.org/rfc/rfc6637.html#section-8>
pub fn derive_session_key(
    shared_secret: &[u8],
    encrypted_session_key: &[u8],
    encrypted_key_len: usize,
    key_params: &<SecretKey as KeyParams>::KeyParams,
    fingerprint: &[u8],
) -> Result<Vec<u8>> {
    let (curve, alg_sym, hash) = key_params;

    let param = build_ecdh_param(&curve.oid(), *alg_sym, *hash, fingerprint);

    // Perform key derivation
    let z = kdf(*hash, shared_secret, alg_sym.key_size(), &param)?;

    // Perform AES Key Unwrap
    let mut encrypted_session_key_vec = vec![0; encrypted_key_len];
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let mut decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;
    // PKCS5-style unpadding (PKCS5 is PKCS7 with a blocksize of 8).
    //
    // RFC 6637 describes the padding:
    // a) "The result is padded using the method described in [PKCS5] to the 8-byte granularity."
    // b) "For example, assuming that an AES algorithm is used for the session key, the sender MAY
    // use 21, 13, and 5 bytes of padding for AES-128, AES-192, and AES-256, respectively, to
    // provide the same number of octets, 40 total, as an input to the key wrapping method."
    //
    // So while the padding ensures that the length of the padded message is a multiple of 8, the
    // padding may exceed 8 bytes in size.
    {
        let len = decrypted_key_padded.len();
        let block_size = 8;
        ensure!(len % block_size == 0, "invalid key length {}", len);
        ensure!(!decrypted_key_padded.is_empty(), "empty key is not valid");

        // The last byte should contain the padding symbol, which is also the padding length
        let pad = decrypted_key_padded.last().expect("is not empty");

        // Padding length seems to exceed size of the padded message
        if *pad as usize > len {
            return Err(Error::UnpadError);
        }

        // Expected length of the unpadded message
        let unpadded_len = len - *pad as usize;

        // All bytes that constitute the padding must have the value of `pad`
        if decrypted_key_padded[unpadded_len..]
            .iter()
            .any(|byte| byte != pad)
        {
            return Err(Error::UnpadError);
        }

        decrypted_key_padded.truncate(unpadded_len);
    }

    // the key is now unpadded
    let decrypted_key = decrypted_key_padded;
    ensure!(!decrypted_key.is_empty(), "empty unpadded key is not valid");

    Ok(decrypted_key)
}

/// Generate an ECDH KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    mut rng: R,
    curve: &ECCCurve,
) -> Result<(PublicParams, PlainSecretParams)> {
    match curve {
        ECCCurve::Curve25519 => {
            let mut secret_key_bytes =
                Zeroizing::new([0u8; ECCCurve::Curve25519.secret_key_length()]);
            rng.fill_bytes(&mut *secret_key_bytes);

            let secret = StaticSecret::from(*secret_key_bytes);
            let public = PublicKey::from(&secret);

            // public key
            let p_raw = public.to_bytes();

            let mut p = Vec::with_capacity(33);
            p.push(0x40);
            p.extend_from_slice(&p_raw);

            // secret key
            // Clamp, as `to_bytes` does not clamp.
            let q_raw = curve25519_dalek::scalar::clamp_integer(secret.to_bytes());
            // Big Endian
            let q = q_raw.into_iter().rev().collect::<Vec<u8>>();

            let curve = ECCCurve::Curve25519;
            let hash = curve.hash_algo()?;
            let alg_sym = curve.sym_algo()?;

            Ok((
                PublicParams::ECDH {
                    curve,
                    p: p.into(),
                    hash,
                    alg_sym,
                },
                PlainSecretParams::ECDH(Mpi::from_raw(q)),
            ))
        }

        ECCCurve::P256 => keygen::<p256::NistP256, R>(rng, curve),

        ECCCurve::P384 => keygen::<p384::NistP384, R>(rng, curve),

        ECCCurve::P521 => keygen::<p521::NistP521, R>(rng, curve),

        _ => unsupported_err!("curve {:?} for ECDH", curve),
    }
}

/// Generate an ECDH key based on a Rust Crypto curve
fn keygen<C, R: Rng + CryptoRng>(
    mut rng: R,
    curve: &ECCCurve,
) -> Result<(PublicParams, PlainSecretParams)>
where
    C: elliptic_curve::CurveArithmetic + elliptic_curve::point::PointCompression,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
{
    let secret = elliptic_curve::SecretKey::<C>::random(&mut rng);
    let public = secret.public_key();

    Ok((
        PublicParams::ECDH {
            curve: curve.clone(),
            p: Mpi::from_raw_slice(public.to_sec1_bytes().as_ref()),
            hash: curve.hash_algo()?,
            alg_sym: curve.sym_algo()?,
        },
        PlainSecretParams::ECDH(Mpi::from_raw_slice(secret.to_bytes().as_slice())),
    ))
}

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// <https://tools.ietf.org/html/rfc6637#section-8>
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash.into(),
        u8::from(alg_sym),
    ];

    let oid_len = [oid.len() as u8];

    let pkalgo = [u8::from(PublicKeyAlgorithm::ECDH)];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &pkalgo,
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// <https://tools.ietf.org/html/rfc6637#section-7>
pub fn kdf(hash: HashAlgorithm, x: &[u8], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

/// PKCS5-style padding, with a block-size of 8.
/// However, the padding may exceed the length of one block, to obfuscate key size.
fn pad(plain: &[u8]) -> Vec<u8> {
    let len = plain.len();

    // We produce "short padding" (between 1 and 8 bytes)
    let remainder = len % 8; // (e.g. 3 for len==19)
    let padded_len = len + 8 - remainder; // (e.g. "8 + 8 - 0 => 16", or "19 + 8 - 3 => 24")
    debug_assert!(padded_len % 8 == 0, "Unexpected padded_len {}", padded_len);

    // The value we'll use for padding (must not be zero, and fit into a u8)
    let padding = padded_len - len;
    debug_assert!(
        padding > 0 && u8::try_from(padding).is_ok(),
        "Unexpected padding value {}",
        padding
    );
    let padding = padding as u8;

    // Extend length of plain_padded, fill with `padding` value
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(padded_len, padding);

    plain_padded
}

/// ECDH encryption.
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    curve: &ECCCurve,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
    q: &[u8],
    plain: &[u8],
) -> Result<EskBytes> {
    debug!("ECDH encrypt");

    // Maximum length for `plain`:
    // - padding increases the length (at least) to a length of the next multiple of 8.
    // - aes keywrap adds another 8 bytes
    // - the maximum length value this function can return is u8 (limited to 255)
    const MAX_SIZE: usize = 239;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (encoded_public, shared_secret) = match curve {
        ECCCurve::Curve25519 => {
            ensure_eq!(q.len(), 33, "invalid public key");

            let their_public = {
                // public part of the ephemeral key (removes 0x40 prefix)
                let public_key = &q[1..];

                // create montgomery point
                let mut public_key_arr = [0u8; 32];
                public_key_arr[..].copy_from_slice(public_key);

                x25519_dalek::PublicKey::from(public_key_arr)
            };

            let mut our_secret_key_bytes =
                Zeroizing::new([0u8; ECCCurve::Curve25519.secret_key_length()]);
            rng.fill_bytes(&mut *our_secret_key_bytes);
            let our_secret = StaticSecret::from(*our_secret_key_bytes);

            // derive shared secret
            let shared_secret = our_secret.diffie_hellman(&their_public);

            // Encode public point: prefix with 0x40
            let mut encoded_public = Vec::with_capacity(33);
            encoded_public.push(0x40);
            encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

            (encoded_public, shared_secret.as_bytes().to_vec())
        }
        ECCCurve::P256 => derive_shared_secret_encryption::<p256::NistP256, R>(rng, q)?,
        ECCCurve::P384 => derive_shared_secret_encryption::<p384::NistP384, R>(rng, q)?,
        ECCCurve::P521 => derive_shared_secret_encryption::<p521::NistP521, R>(rng, q)?,
        _ => unsupported_err!("curve {:?} for ECDH", curve),
    };

    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    // Perform key derivation
    let z = kdf(hash, &shared_secret, alg_sym.key_size(), &param)?;

    // Pad plaintext
    let plain_padded = pad(plain);

    // Perform AES Key Wrap
    let encrypted_session_key = aes_kw::wrap(&z, &plain_padded)?;

    Ok(EskBytes::Ecdh {
        public_point: Mpi::from_raw_slice(&encoded_public),
        encrypted_session_key,
    })
}

/// Derive a shared secret in encryption, for a Rust Crypto curve.
/// Returns a pair of `(our_public key, shared_secret)`.
fn derive_shared_secret_encryption<C, R: CryptoRng + Rng>(
    mut rng: R,
    q: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::CurveArithmetic + elliptic_curve::point::PointCompression,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
{
    let their_public = elliptic_curve::PublicKey::<C>::from_sec1_bytes(q)?;
    let our_secret = elliptic_curve::ecdh::EphemeralSecret::<C>::random(&mut rng);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // encode our public key
    let our_public = elliptic_curve::PublicKey::<C>::from(&our_secret);
    let our_public = elliptic_curve::sec1::EncodedPoint::<C>::from(our_public);

    Ok((
        our_public.as_bytes().to_vec(),
        shared_secret.raw_secret_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::types::SecretKeyRepr;
    use crate::{Deserializable, Message, SignedSecretKey};

    #[test]
    fn test_encrypt_decrypt() {
        for curve in [
            ECCCurve::Curve25519,
            ECCCurve::P256,
            ECCCurve::P384,
            ECCCurve::P521,
        ] {
            let mut rng = ChaChaRng::from_seed([0u8; 32]);

            let (pkey, skey) = generate_key(&mut rng, &curve).unwrap();

            for text_size in 1..=239 {
                for _i in 0..10 {
                    let mut fingerprint = vec![0u8; 20];
                    rng.fill_bytes(&mut fingerprint);

                    let mut plain = vec![0u8; text_size];
                    rng.fill_bytes(&mut plain);

                    let values = match pkey {
                        PublicParams::ECDH {
                            ref curve,
                            ref p,
                            hash,
                            alg_sym,
                        } => encrypt(
                            &mut rng,
                            curve,
                            alg_sym,
                            hash,
                            &fingerprint,
                            p.as_bytes(),
                            &plain[..],
                        )
                        .unwrap(),
                        _ => panic!("invalid key generated"),
                    };

                    let decrypted = match (skey.as_ref().as_repr(&pkey).unwrap(), values) {
                        (
                            SecretKeyRepr::ECDH(ref skey),
                            EskBytes::Ecdh {
                                public_point,
                                encrypted_session_key,
                            },
                        ) => skey
                            .decrypt((&public_point, &encrypted_session_key, &fingerprint))
                            .unwrap(),
                        _ => panic!("invalid key generated"),
                    };

                    assert_eq!(&plain[..], &decrypted[..]);
                }
            }
        }
    }

    #[test]
    fn test_decrypt_padding() {
        let (decrypt_key, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/unit-tests/padding/alice.key").unwrap(),
        )
        .expect("failed to read decryption key");

        for msg_file in [
            "./tests/unit-tests/padding/msg-short-padding.pgp",
            "./tests/unit-tests/padding/msg-long-padding.pgp",
        ] {
            let (message, _headers) = Message::from_armor_single(fs::File::open(msg_file).unwrap())
                .expect("failed to parse message");

            let (msg, _ids) = message
                .decrypt(String::default, &[&decrypt_key])
                .expect("failed to init decryption");

            let data = msg.get_literal().unwrap().data();

            assert_eq!(data, "hello\n".as_bytes());
        }
    }
}
