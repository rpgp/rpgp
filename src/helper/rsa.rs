use std::{fmt, marker::PhantomData};

use chrono::{DateTime, Utc};
use digest::{typenum::Unsigned, OutputSizeUser};
use rand::{CryptoRng, Rng};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    traits::PublicKeyParts,
    RsaPublicKey,
};
use sha2::Digest;
use signature::{hazmat::PrehashSigner, Keypair, SignatureEncoding};

use crate::{
    bail,
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::PublicKey,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Mpi, PkeskBytes, PublicKeyTrait, PublicParams,
        SecretKeyTrait, SignatureBytes, Version,
    },
};

use super::{PgpHash, PgpPublicKey};

impl PgpPublicKey for RsaPublicKey {
    const PGP_ALGORITHM: PublicKeyAlgorithm = PublicKeyAlgorithm::RSA;

    fn pgp_parameters(&self) -> PublicParams {
        PublicParams::RSA {
            n: self.n().into(),
            e: self.e().into(),
        }
    }
}

/// [`signature::Signer`] backed signer for PGP.
pub struct RsaSigner<T, D> {
    inner: T,
    public_key: PublicKey,
    _digest: PhantomData<D>,
}

impl<D, T> fmt::Debug for RsaSigner<T, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner").finish()
    }
}

impl<T, D> RsaSigner<T, D>
where
    D: Digest,
    T: Keypair<VerifyingKey = VerifyingKey<D>>,
{
    /// Create a new signer with a given public key
    pub fn new(inner: T, created_at: DateTime<Utc>) -> Result<Self> {
        let public_key = PublicKey::new(
            Version::New,
            KeyVersion::V4,
            RsaPublicKey::PGP_ALGORITHM,
            created_at,
            None,
            inner.verifying_key().as_ref().pgp_parameters(),
        )?;

        Ok(Self {
            inner,
            public_key,
            _digest: PhantomData,
        })
    }
}

impl<D, T> RsaSigner<T, D>
where
    D: Digest + PgpHash,
    T: PrehashSigner<Signature>,
{
    fn sign_prehash(&self, hash: HashAlgorithm, prehash: &[u8]) -> Result<Vec<Vec<u8>>> {
        if D::HASH_ALGORITHM != hash {
            bail!(
                "Signer only support {expected:?}, found {found:?}",
                expected = D::HASH_ALGORITHM,
                found = hash
            );
        }

        if <D as OutputSizeUser>::OutputSize::USIZE != prehash.len() {
            bail!(
                "Signer expected a hash of length ({expected} bytes), found ({found} bytes)",
                expected = <D as OutputSizeUser>::OutputSize::USIZE,
                found = prehash.len()
            );
        }

        let sig = self.inner.sign_prehash(prehash)?;

        Ok(vec![sig.to_vec()])
    }
}

impl<D, T> Keypair for RsaSigner<T, D>
where
    T: Keypair,
{
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl<D, T> SecretKeyTrait for RsaSigner<T, D>
where
    T: PrehashSigner<Signature>,
    D: Digest + PgpHash,
{
    type PublicKey = PublicKey;
    type Unlocked = Self;

    fn unlock<F, G, Tr>(&self, _pw: F, work: G) -> Result<Tr>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<Tr>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        hash: HashAlgorithm,
        prehashed_data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        let sig = self.sign_prehash(hash, prehashed_data)?;

        // MPI format:
        // strip leading zeros, to match parse results from MPIs
        let mpis = sig
            .iter()
            .map(|v| Mpi::from_slice(&v[..]))
            .collect::<Vec<_>>();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn hash_alg(&self) -> HashAlgorithm {
        D::HASH_ALGORITHM
    }
}

impl<D, T> PublicKeyTrait for RsaSigner<T, D> {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        _rng: R,
        _plain: &[u8],
        _esk_type: EskType,
    ) -> Result<PkeskBytes> {
        bail!("Encryption is unsupported")
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        self.public_key.serialize_for_hashing(writer)
    }

    fn version(&self) -> KeyVersion {
        self.public_key.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.public_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.public_key.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }

    fn is_encryption_key(&self) -> bool {
        false
    }
}
