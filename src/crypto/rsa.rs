use digest::{const_oid::AssociatedOid, Digest};
use md5::Md5;
use num_bigint::traits::ModInverse;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use ripemd::Ripemd160;
use rsa::pkcs1v15::{Pkcs1v15Encrypt, Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::{PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::SignatureEncoding;

use crate::crypto::hash::HashAlgorithm;
use crate::errors::Result;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

const MAX_KEY_SIZE: usize = 16384;

/// RSA decryption using PKCS1v15 padding.
pub fn decrypt(priv_key: &RsaPrivateKey, mpis: &[Mpi], _fingerprint: &[u8]) -> Result<Vec<u8>> {
    // rsa consist of exactly one mpi
    ensure_eq!(mpis.len(), 1, "invalid input");

    let mpi = &mpis[0];
    let m = priv_key.decrypt(Pkcs1v15Encrypt, mpi.as_bytes())?;

    Ok(m)
}

/// RSA encryption using PKCS1v15 padding.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    n: &[u8],
    e: &[u8],
    plaintext: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        MAX_KEY_SIZE,
    )?;
    let data = key.encrypt(rng, Pkcs1v15Encrypt, plaintext)?;

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

fn verify_int<D>(key: RsaPublicKey, hashed: &[u8], signature: &RsaSignature) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    VerifyingKey::<D>::new_with_prefix(key)
        .verify_prehash(hashed, signature)
        .map_err(Into::into)
}

fn sign_int<D>(key: RsaPrivateKey, digest: &[u8]) -> Result<RsaSignature>
where
    D: Digest + AssociatedOid,
{
    SigningKey::<D>::new_with_prefix(key)
        .sign_prehash(digest)
        .map_err(Into::into)
}

/// Verify a RSA, PKCS1v15 padded signature.
pub fn verify(
    n: &[u8],
    e: &[u8],
    hash: HashAlgorithm,
    hashed: &[u8],
    signature: &[u8],
) -> Result<()> {
    let signature = RsaSignature::try_from(signature)?;
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        MAX_KEY_SIZE,
    )?;

    match hash {
        HashAlgorithm::None => Err(format_err!("none")),
        HashAlgorithm::MD5 => verify_int::<Md5>(key, hashed, &signature),
        HashAlgorithm::RIPEMD160 => verify_int::<Ripemd160>(key, hashed, &signature),
        HashAlgorithm::SHA1 => verify_int::<Sha1>(key, hashed, &signature),
        HashAlgorithm::SHA2_224 => verify_int::<Sha224>(key, hashed, &signature),
        HashAlgorithm::SHA2_256 => verify_int::<Sha256>(key, hashed, &signature),
        HashAlgorithm::SHA2_384 => verify_int::<Sha384>(key, hashed, &signature),
        HashAlgorithm::SHA2_512 => verify_int::<Sha512>(key, hashed, &signature),
        HashAlgorithm::SHA3_256 => verify_int::<Sha3_256>(key, hashed, &signature),
        HashAlgorithm::SHA3_512 => verify_int::<Sha3_512>(key, hashed, &signature),
        HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
    }
    .map_err(Into::into)
}

/// Sign using RSA, with PKCS1v15 padding.
pub fn sign(key: &RsaPrivateKey, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    let sig = match hash {
        HashAlgorithm::None => return Err(format_err!("none")),
        HashAlgorithm::MD5 => sign_int::<Md5>(key.clone(), digest),
        HashAlgorithm::RIPEMD160 => sign_int::<Ripemd160>(key.clone(), digest),
        HashAlgorithm::SHA1 => sign_int::<Sha1>(key.clone(), digest),
        HashAlgorithm::SHA2_224 => sign_int::<Sha224>(key.clone(), digest),
        HashAlgorithm::SHA2_256 => sign_int::<Sha256>(key.clone(), digest),
        HashAlgorithm::SHA2_384 => sign_int::<Sha384>(key.clone(), digest),
        HashAlgorithm::SHA2_512 => sign_int::<Sha512>(key.clone(), digest),
        HashAlgorithm::SHA3_256 => sign_int::<Sha3_256>(key.clone(), digest),
        HashAlgorithm::SHA3_512 => sign_int::<Sha3_512>(key.clone(), digest),
        HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
    }?;

    Ok(vec![sig.to_vec()])
}
