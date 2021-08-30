use num_bigint::traits::ModInverse;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use try_from::TryInto;

use crate::crypto::HashAlgorithm;
use crate::errors::Result;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

/// RSA decryption using PKCS1v15 padding.
pub fn decrypt(priv_key: &RsaPrivateKey, mpis: &[Mpi], _fingerprint: &[u8]) -> Result<Vec<u8>> {
    // rsa consist of exactly one mpi
    ensure_eq!(mpis.len(), 1, "invalid input");

    let mpi = &mpis[0];
    let m = priv_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), mpi.as_bytes())?;

    Ok(m)
}

/// RSA encryption using PKCS1v15 padding.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    n: &[u8],
    e: &[u8],
    plaintext: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))?;
    let data = key.encrypt(rng, PaddingScheme::new_pkcs1v15_encrypt(), plaintext)?;

    Ok(vec![data])
}

/// Generate an RSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    rng: &mut R,
    bit_size: usize,
) -> Result<(PublicParams, PlainSecretParams)> {
    let key = RsaPrivateKey::new(rng, bit_size)?;

    let p = &key.primes()[0];
    let q = &key.primes()[1];
    let u = p
        .clone()
        .mod_inverse(q)
        .expect("invalid prime")
        .to_biguint()
        .expect("invalid prime");

    Ok((
        PublicParams::RSA {
            n: key.n().into(),
            e: key.e().into(),
        },
        PlainSecretParams::RSA {
            d: key.d().into(),
            p: p.into(),
            q: q.into(),
            u: u.into(),
        },
    ))
}

/// Verify a RSA, PKCS1v15 padded signature.
pub fn verify(n: &[u8], e: &[u8], hash: HashAlgorithm, hashed: &[u8], sig: &[u8]) -> Result<()> {
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))?;
    let rsa_hash: Option<rsa::Hash> = hash.try_into().ok();

    key.verify(PaddingScheme::new_pkcs1v15_sign(rsa_hash), &hashed[..], sig)
        .map_err(Into::into)
}

/// Sign using RSA, with PKCS1v15 padding.
pub fn sign(key: &RsaPrivateKey, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    let rsa_hash: Option<rsa::Hash> = hash.try_into().ok();
    let sig = key.sign(PaddingScheme::new_pkcs1v15_sign(rsa_hash), digest)?;

    Ok(vec![sig])
}
