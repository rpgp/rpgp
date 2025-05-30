use digest::{const_oid::AssociatedOid, Digest};
use md5::Md5;
use num_bigint::ModInverse;
use rand::{CryptoRng, Rng};
use ripemd::Ripemd160;
use rsa::{
    pkcs1v15::{Pkcs1v15Encrypt, Signature as RsaSignature, SigningKey, VerifyingKey},
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey, RsaPublicKey,
};
use sha1_checked::Sha1; // not used for hashing, just as a source of the OID
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    SignatureEncoding,
};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{hash::HashAlgorithm, Decryptor, Signer},
    errors::{format_err, unsupported_err, Result},
    ser::Serialize,
    types::{Mpi, PkeskBytes, RsaPublicParams, SignatureBytes},
};

pub(crate) const MAX_KEY_SIZE: usize = 16384;

/// Private Key for RSA.
#[derive(derive_more::Debug, ZeroizeOnDrop, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKey(
    #[debug("..")]
    #[cfg_attr(test, proptest(strategy = "tests::key_gen()"))]
    RsaPrivateKey,
);

impl SecretKey {
    /// Generate an RSA `SecretKey`.
    ///
    /// Errors on unsupported `bit_size`s.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R, bit_size: usize) -> Result<Self> {
        let key = RsaPrivateKey::new(&mut rng, bit_size)?;

        Ok(SecretKey(key))
    }

    pub(crate) fn try_from_mpi(
        pub_params: &RsaPublicParams,
        d: Mpi,
        p: Mpi,
        q: Mpi,
        _u: Mpi,
    ) -> Result<Self> {
        let secret_key = RsaPrivateKey::from_components(
            pub_params.key.n().clone(),
            pub_params.key.e().clone(),
            d.into(),
            vec![p.into(), q.into()],
        )?;
        Ok(Self(secret_key))
    }

    /// Returns `d`, `p`, `q`, `u` as MPIs
    fn to_mpi(&self) -> (Mpi, Mpi, Mpi, Mpi) {
        let d = self.0.d();
        let p = &self.0.primes()[0];
        let q = &self.0.primes()[1];
        let u = p
            .clone()
            .mod_inverse(q)
            .expect("invalid prime")
            .to_biguint()
            .expect("invalid prime");

        (Mpi::from(d), Mpi::from(p), Mpi::from(q), Mpi::from(u))
    }

    /// Returns the modulus size in bytes.
    pub fn size(&self) -> usize {
        self.0.size()
    }

    /// Returns `d`, `p`, `q`, `u` in big endian
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let d = self.0.d().to_bytes_be();
        let p = self.0.primes()[0].to_bytes_be();
        let q = self.0.primes()[1].to_bytes_be();
        let u = self.0.primes()[0]
            .clone()
            .mod_inverse(&self.0.primes()[1])
            .expect("invalid prime")
            .to_biguint()
            .expect("invalid prime")
            .to_bytes_be();

        (d, p, q, u)
    }
}

impl From<&SecretKey> for RsaPublicParams {
    fn from(value: &SecretKey) -> Self {
        RsaPublicParams {
            key: value.0.to_public_key(),
        }
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let (d, p, q, u) = self.to_mpi();
        d.to_writer(writer)?;
        p.to_writer(writer)?;
        q.to_writer(writer)?;
        u.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        let (d, p, q, u) = self.to_mpi();
        sum += d.write_len();
        sum += p.write_len();
        sum += q.write_len();
        sum += u.write_len();
        sum
    }
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = &'a Mpi;

    /// RSA decryption using PKCS1v15 padding.
    fn decrypt(&self, mpi: Self::EncryptionFields<'_>) -> Result<Vec<u8>> {
        let m = self.0.decrypt(Pkcs1v15Encrypt, mpi.as_ref())?;

        Ok(m)
    }
}

impl Signer for SecretKey {
    /// Sign using RSA, with PKCS1v15 padding.
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        let sig = match hash {
            HashAlgorithm::None => return Err(format_err!("none")),
            HashAlgorithm::Md5 => sign_int::<Md5>(self.0.clone(), digest),
            HashAlgorithm::Ripemd160 => sign_int::<Ripemd160>(self.0.clone(), digest),
            HashAlgorithm::Sha1 => sign_int::<Sha1>(self.0.clone(), digest),
            HashAlgorithm::Sha224 => sign_int::<Sha224>(self.0.clone(), digest),
            HashAlgorithm::Sha256 => sign_int::<Sha256>(self.0.clone(), digest),
            HashAlgorithm::Sha384 => sign_int::<Sha384>(self.0.clone(), digest),
            HashAlgorithm::Sha512 => sign_int::<Sha512>(self.0.clone(), digest),
            HashAlgorithm::Sha3_256 => sign_int::<Sha3_256>(self.0.clone(), digest),
            HashAlgorithm::Sha3_512 => sign_int::<Sha3_512>(self.0.clone(), digest),
            HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
            HashAlgorithm::Other(o) => unsupported_err!("Hash algorithm {} is unsupported", o),
        }?;

        Ok(SignatureBytes::Mpis(vec![Mpi::from_slice(&sig.to_bytes())]))
    }
}

impl From<RsaPrivateKey> for SecretKey {
    fn from(key: RsaPrivateKey) -> Self {
        Self(key)
    }
}

/// RSA encryption using PKCS1v15 padding.
pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    key: &RsaPublicKey,
    plaintext: &[u8],
) -> Result<PkeskBytes> {
    let data = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)?;

    Ok(PkeskBytes::Rsa {
        mpi: Mpi::from_slice(&data[..]),
    })
}

fn verify_int<D>(key: &RsaPublicKey, hashed: &[u8], signature: &RsaSignature) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    VerifyingKey::<D>::new(key.clone())
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
    key: &rsa::RsaPublicKey,
    hash: HashAlgorithm,
    hashed: &[u8],
    signature: &[u8],
) -> Result<()> {
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
        HashAlgorithm::Md5 => verify_int::<Md5>(key, hashed, &signature),
        HashAlgorithm::Ripemd160 => verify_int::<Ripemd160>(key, hashed, &signature),
        HashAlgorithm::Sha1 => verify_int::<Sha1>(key, hashed, &signature),
        HashAlgorithm::Sha224 => verify_int::<Sha224>(key, hashed, &signature),
        HashAlgorithm::Sha256 => verify_int::<Sha256>(key, hashed, &signature),
        HashAlgorithm::Sha384 => verify_int::<Sha384>(key, hashed, &signature),
        HashAlgorithm::Sha512 => verify_int::<Sha512>(key, hashed, &signature),
        HashAlgorithm::Sha3_256 => verify_int::<Sha3_256>(key, hashed, &signature),
        HashAlgorithm::Sha3_512 => verify_int::<Sha3_512>(key, hashed, &signature),
        HashAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
        HashAlgorithm::Other(o) => unsupported_err!("Hash algorithm {} is unsupported", o),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    prop_compose! {
        pub fn key_gen()(seed: u64) -> RsaPrivateKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            RsaPrivateKey::new(&mut rng, 512).unwrap()
        }
    }
}
