use std::{fmt, marker::PhantomData};

use chrono::{DateTime, Utc};
use digest::{typenum::Unsigned, OutputSizeUser};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    RsaPublicKey,
};
use sha2::Digest;
use signature::{hazmat::PrehashSigner, Keypair, SignatureEncoding};

use super::{PgpHash, PgpPublicKey};
use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, Result},
    packet::{PubKeyInner, PublicKey},
    types::{
        Fingerprint, KeyDetails, KeyId, KeyVersion, Mpi, Password, PublicKeyTrait, PublicParams,
        RsaPublicParams, SecretKeyTrait, SignatureBytes,
    },
};

impl PgpPublicKey for RsaPublicKey {
    const PGP_ALGORITHM: PublicKeyAlgorithm = PublicKeyAlgorithm::RSA;

    fn pgp_parameters(&self) -> PublicParams {
        PublicParams::RSA(RsaPublicParams { key: self.clone() })
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
        let public_key = PubKeyInner::new(
            KeyVersion::V4,
            RsaPublicKey::PGP_ALGORITHM,
            created_at,
            None,
            inner.verifying_key().as_ref().pgp_parameters(),
        )?;

        Ok(Self {
            inner,
            public_key: PublicKey::from_inner(public_key)?,
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
    fn create_signature(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        prehashed_data: &[u8],
    ) -> Result<SignatureBytes> {
        let sig = self.sign_prehash(hash, prehashed_data)?;

        // MPI format:
        // strip leading zeros, to match parse results from MPIs
        let mpis = sig
            .iter()
            .map(|v| Mpi::from_slice(&v[..]))
            .collect::<Vec<_>>();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        D::HASH_ALGORITHM
    }
}

impl<D, T> KeyDetails for RsaSigner<T, D> {
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
