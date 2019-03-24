use num_bigint::traits::ModInverse;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
use try_from::TryInto;

use crypto::HashAlgorithm;
use errors::Result;
use types::{PlainSecretParams, PublicParams};

/// RSA decryption using PKCS1v15 padding.
pub fn decrypt(priv_key: &RSAPrivateKey, mpis: &[Vec<u8>], _fingerprint: &[u8]) -> Result<Vec<u8>> {
    // rsa consist of exactly one mpi
    let mpi = &mpis[0];
    info!("RSA m^e mod n: {}", hex::encode(mpi));
    let m = priv_key.decrypt(PaddingScheme::PKCS1v15, mpi)?;
    info!("m: {}", hex::encode(&m));

    Ok(m)
}

/// RSA encryption using PKCS1v15 padding.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    n: &[u8],
    e: &[u8],
    plaintext: &[u8],
) -> Result<Vec<Vec<u8>>> {
    info!("RSA encrypt");

    let key = RSAPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))?;
    let data = key.encrypt(rng, PaddingScheme::PKCS1v15, plaintext)?;

    Ok(vec![data])
}

/// Generate an RSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    rng: &mut R,
    bit_size: usize,
) -> Result<(PublicParams, PlainSecretParams)> {
    let key = RSAPrivateKey::new(rng, bit_size)?;

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
            n: key.n().to_bytes_be(),
            e: key.e().to_bytes_be(),
        },
        PlainSecretParams::RSA {
            d: key.d().to_bytes_be(),
            p: p.to_bytes_be(),
            q: q.to_bytes_be(),
            u: u.to_bytes_be(),
        },
    ))
}

/// Verify a RSA, PKCS1v15 padded signature.
pub fn verify(n: &[u8], e: &[u8], hash: HashAlgorithm, hashed: &[u8], sig: &[u8]) -> Result<()> {
    let key = RSAPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))?;
    let rsa_hash: Option<rsa::hash::Hashes> = hash.try_into().ok();

    info!("n: {}", hex::encode(n));
    info!("e: {}", hex::encode(e));
    key.verify(PaddingScheme::PKCS1v15, rsa_hash.as_ref(), &hashed[..], sig)
        .map_err(Into::into)
}

/// Sign using RSA, with PKCS1v15 padding.
pub fn sign(key: &RSAPrivateKey, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    let rsa_hash: Option<rsa::hash::Hashes> = hash.try_into().ok();
    let sig = key.sign(PaddingScheme::PKCS1v15, rsa_hash.as_ref(), digest)?;

    Ok(vec![sig])
}
