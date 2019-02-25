use num_bigint::traits::ModInverse;
use rand::{CryptoRng, Rng};
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, RSAPrivateKey};

use crypto::PublicParams;
use errors::Result;
use types::PlainSecretParams;

pub fn decrypt_rsa(
    priv_key: &RSAPrivateKey,
    mpis: &[Vec<u8>],
    _fingerprint: &[u8],
) -> Result<Vec<u8>> {
    // rsa consist of exactly one mpi
    let mpi = &mpis[0];
    info!("RSA m^e mod n: {}", hex::encode(mpi));
    let m = priv_key.decrypt(PaddingScheme::PKCS1v15, mpi)?;
    info!("m: {}", hex::encode(&m));

    Ok(m)
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
            n: key.n().clone(),
            e: key.e().clone(),
        },
        PlainSecretParams::RSA {
            d: key.d().clone(),
            p: p.clone(),
            q: q.clone(),
            u,
        },
    ))
}
