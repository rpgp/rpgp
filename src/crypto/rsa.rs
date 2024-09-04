use std::ops::Deref;

use digest::{const_oid::AssociatedOid, Digest};
use md5::Md5;
use num_bigint::traits::ModInverse;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use ripemd::Ripemd160;
use rsa::pkcs1v15::{Pkcs1v15Encrypt, Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey, RsaPublicKey,
};
use sha1_checked::Sha1; // not used for hashing, just as a source of the OID
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::SignatureEncoding;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{hash::HashAlgorithm, Decryptor, KeyParams, Signer};
use crate::errors::Result;
use crate::types::PkeskBytes;
use crate::types::{Mpi, PlainSecretParams, PublicParams};

const MAX_KEY_SIZE: usize = 16384;

/// Private Key for RSA.
#[derive(derive_more::Debug, ZeroizeOnDrop)]
pub struct PrivateKey(#[debug("..")] pub(crate) RsaPrivateKey);

impl Deref for PrivateKey {
    type Target = RsaPrivateKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyParams for PrivateKey {
    type KeyParams = ();

    #[allow(clippy::unused_unit)]
    fn key_params(&self) -> Self::KeyParams {
        ()
    }
}

impl Decryptor for PrivateKey {
    type EncryptionFields<'a> = &'a Mpi;

    /// RSA decryption using PKCS1v15 padding.
    fn decrypt(&self, mpi: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        let m = self.0.decrypt(Pkcs1v15Encrypt, mpi.as_bytes())?;

        Ok(m)
    }
}

impl Signer for PrivateKey {
    /// Sign using RSA, with PKCS1v15 padding.
    fn sign(
        &self,
        hash: HashAlgorithm,
        digest: &[u8],
        pub_params: &PublicParams,
    ) -> Result<Vec<Vec<u8>>> {
        ensure!(
            matches!(pub_params, PublicParams::RSA { .. }),
            "invalid public params"
        );

        let sig = match hash {
            HashAlgorithm::None => return Err(format_err!("none")),
            HashAlgorithm::MD5 => sign_int::<Md5>(self.0.clone(), digest),
            HashAlgorithm::RIPEMD160 => sign_int::<Ripemd160>(self.0.clone(), digest),
            HashAlgorithm::SHA1 => sign_int::<Sha1>(self.0.clone(), digest),
            HashAlgorithm::SHA2_224 => sign_int::<Sha224>(self.0.clone(), digest),
            HashAlgorithm::SHA2_256 => sign_int::<Sha256>(self.0.clone(), digest),
            HashAlgorithm::SHA2_384 => sign_int::<Sha384>(self.0.clone(), digest),
            HashAlgorithm::SHA2_512 => sign_int::<Sha512>(self.0.clone(), digest),
            HashAlgorithm::SHA3_256 => sign_int::<Sha3_256>(self.0.clone(), digest),
            HashAlgorithm::SHA3_512 => sign_int::<Sha3_512>(self.0.clone(), digest),
            HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
            HashAlgorithm::Other(o) => unsupported_err!("Hash algorithm {} is unsupported", o),
        }?;

        Ok(vec![sig.to_vec()])
    }
}

/// RSA encryption using PKCS1v15 padding.
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    n: &[u8],
    e: &[u8],
    plaintext: &[u8],
) -> Result<PkeskBytes> {
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        MAX_KEY_SIZE,
    )?;
    let data = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)?;

    Ok(PkeskBytes::Rsa {
        mpi: Mpi::from_raw_slice(&data[..]),
    })
}

/// Generate an RSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(
    mut rng: R,
    bit_size: usize,
) -> Result<(PublicParams, PlainSecretParams)> {
    let key = RsaPrivateKey::new(&mut rng, bit_size)?;

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
    VerifyingKey::<D>::new(key)
        .verify_prehash(hashed, signature)
        .map_err(Into::into)
}

fn sign_int<D>(key: RsaPrivateKey, digest: &[u8]) -> Result<RsaSignature>
where
    D: Digest + AssociatedOid,
{
    SigningKey::<D>::new(key)
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
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        MAX_KEY_SIZE,
    )?;

    let signature = if signature.len() < key.size() {
        // RSA short signatures are allowed by PGP, but not by the RSA crate.
        // So we pad out the signature if we encounter a short one.
        let mut signature_padded = vec![0u8; key.size()];
        let diff = key.size() - signature.len();
        signature_padded[diff..].copy_from_slice(signature);
        RsaSignature::try_from(&signature_padded[..])?
    } else {
        RsaSignature::try_from(signature)?
    };

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
        HashAlgorithm::Other(o) => unsupported_err!("Hash algorithm {} is unsupported", o),
    }
    .map_err(Into::into)
}
