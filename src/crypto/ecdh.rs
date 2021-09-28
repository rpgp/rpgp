use std::convert::TryInto;
use std::ops::Add;

use block_padding::{Padding, Pkcs7};
use elliptic_curve::{
    consts::U1,
    ecdh::SharedSecret,
    generic_array::ArrayLength,
    group::Curve,
    sec1::{FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize},
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{aes_kw, ECCCurve, HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use crate::errors::Result;
use crate::types::{ECDHSecretKey, Mpi, PlainSecretParams, PublicParams};

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

const SECRET_KEY_LENGTH: usize = 32;

/// Generate an ECDH KeyPair.
/// Currently only support ED25519.
pub fn generate_key<R: Rng + CryptoRng>(rng: &mut R) -> (PublicParams, PlainSecretParams) {
    let mut secret_key_bytes = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *secret_key_bytes);

    let secret = StaticSecret::from(*secret_key_bytes);
    let public = PublicKey::from(&secret);

    // public key
    let mut p = Vec::with_capacity(33);
    p.push(0x40);
    p.extend_from_slice(&public.as_bytes()[..]);

    // secret key
    let q = secret.to_bytes().iter().cloned().rev().collect::<Vec<u8>>();

    // TODO: make these configurable and/or check for good defaults
    let hash = HashAlgorithm::default();
    let alg_sym = SymmetricKeyAlgorithm::AES128;
    (
        PublicParams::ECDH {
            curve: ECCCurve::Curve25519,
            p: p.into(),
            hash,
            alg_sym,
        },
        PlainSecretParams::ECDH(Mpi::from_raw(q)),
    )
}

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// https://tools.ietf.org/html/rfc6637#section-8
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ];

    let oid_len = [oid.len() as u8];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &[PublicKeyAlgorithm::ECDH as u8],
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// ECDH decryption.
pub fn decrypt(priv_key: &ECDHSecretKey, mpis: &[Mpi], fingerprint: &[u8]) -> Result<Vec<u8>> {
    debug!("ECDH ({}) decrypt", priv_key.curve.to_string());
    ensure_eq!(mpis.len(), 3);

    let param = build_ecdh_param(&priv_key.oid, priv_key.alg_sym, priv_key.hash, fingerprint);
    let secret_point = &priv_key.secret;
    let public_point = mpis[0].as_bytes();

    let shared_secret = match priv_key.curve {
        ECCCurve::Curve25519 => generate_shared_secret_curve25519(secret_point, public_point)?,
        ECCCurve::P256 => generate_shared_secret_ecc::<p256::NistP256>(secret_point, public_point)?,
        ECCCurve::P384
        | ECCCurve::P521
        | ECCCurve::Secp256k1
        | ECCCurve::BrainpoolP256r1
        | ECCCurve::BrainpoolP384r1
        | ECCCurve::BrainpoolP512r1 => {
            unimplemented_err!("ECDH curve: {}", priv_key.curve.to_string())
        }
        _ => {
            unsupported_err!("ECDH curve: {}", priv_key.curve.to_string())
        }
    };

    // Perform key derivation
    let z = kdf(
        priv_key.hash,
        &shared_secret,
        priv_key.alg_sym.key_size(),
        &param,
    )?;

    // Peform AES Key Unwrap
    let encrypted_key_len: usize = match mpis[1].first() {
        Some(l) => *l as usize,
        None => 0,
    };

    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = mpis[2].as_bytes();

    let mut encrypted_session_key_vec: Vec<u8> = Vec::new();
    encrypted_session_key_vec.resize(encrypted_key_len, 0);
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;

    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    let decrypted_key = Pkcs7::unpad(&decrypted_key_padded)?;

    Ok(decrypted_key.to_vec())
}

fn generate_shared_secret_curve25519(secret_point: &[u8], public_point: &[u8]) -> Result<[u8; 32]> {
    // 33 = 0x40 + 32bits
    ensure_eq!(public_point.len(), 33, "invalid public point");
    ensure_eq!(secret_point.len(), 32, "invalid secret point");

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let ephemeral_public_key = &public_point[1..];

        // create montgomery point
        let mut ephemeral_public_key_arr = [0u8; 32];
        ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

        x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
    };

    let our_secret = {
        // create scalar and reverse to little endian
        let mut private_key_le = secret_point.iter().rev().cloned().collect::<Vec<u8>>();
        let mut private_key_arr = [0u8; 32];
        private_key_arr[..].copy_from_slice(&private_key_le);
        private_key_le.zeroize();

        x25519_dalek::StaticSecret::from(private_key_arr)
    };

    // derive shared secret
    let shared_secret = *our_secret.diffie_hellman(&their_public).as_bytes();
    Ok(shared_secret)
}

fn generate_shared_secret_ecc<C>(secret_point: &[u8], public_point: &[u8]) -> Result<[u8; 32]>
where
    C: ecdsa::Curve + elliptic_curve::ProjectiveArithmetic,
    Scalar<C>: Zeroize,
    AffinePoint<C>: Zeroize + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SharedSecret<C>: for<'a> From<&'a AffinePoint<C>>,
{
    ensure_eq!(public_point.len(), 65, "invalid public point");
    ensure_eq!(secret_point.len(), 32, "invalid secret point");

    let their_public = elliptic_curve::PublicKey::<C>::from_sec1_bytes(public_point)?;
    let our_secret = elliptic_curve::SecretKey::<C>::from_bytes(secret_point)?;

    // derive shared secret
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        our_secret.to_secret_scalar(),
        their_public.as_affine(),
    );
    let shared_secret = shared_secret.as_bytes().to_vec();
    let shared_secret = shared_secret.try_into().expect("must be 32 bytes");
    Ok(shared_secret)
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// https://tools.ietf.org/html/rfc6637#section-7
fn kdf(hash: HashAlgorithm, x: &[u8; 32], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

/// ECDH encryption.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    curve: &ECCCurve,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
    q: &[u8],
    plain: &[u8],
) -> Result<Vec<Vec<u8>>> {
    debug!("ECDH encrypt");

    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    ensure_eq!(q.len(), 33, "invalid public key");

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let public_key = &q[1..];

        // create montgomery point
        let mut public_key_arr = [0u8; 32];
        public_key_arr[..].copy_from_slice(public_key);

        x25519_dalek::PublicKey::from(public_key_arr)
    };

    let mut our_secret_key_bytes = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *our_secret_key_bytes);
    let our_secret = x25519_dalek::StaticSecret::from(*our_secret_key_bytes);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // Perform key derivation
    let z = kdf(hash, shared_secret.as_bytes(), alg_sym.key_size(), &param)?;

    // PKCS5 padding (PKCS5 is PKCS7 with a blocksize of 8)
    let len = plain.len();
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(len + 8, 0);
    let plain_padded_ref = Pkcs7::pad(&mut plain_padded, len, 8)?;

    // Peform AES Key Wrap
    let encrypted_key = aes_kw::wrap(&z, plain_padded_ref)?;

    // Encode public point: prefix with 0x40
    let mut encoded_public = Vec::with_capacity(33);
    encoded_public.push(0x40);
    encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

    let encrypted_key_len = vec![encrypted_key.len() as u8];

    Ok(vec![encoded_public, encrypted_key_len, encrypted_key])
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use crate::types::{PublicParams, SecretKeyRepr};

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let (pkey, skey) = generate_key(&mut rng);
        let mut fingerprint = vec![0u8; 20];
        rng.fill_bytes(&mut fingerprint);

        let plain = b"hello world";

        let mpis = match pkey {
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

        let mpis = mpis.into_iter().map(Into::into).collect::<Vec<Mpi>>();

        let decrypted = match skey.as_ref().as_repr(&pkey).unwrap() {
            SecretKeyRepr::ECDH(ref skey) => decrypt(skey, &mpis, &fingerprint).unwrap(),
            _ => panic!("invalid key generated"),
        };

        assert_eq!(&plain[..], &decrypted[..]);
    }
}
