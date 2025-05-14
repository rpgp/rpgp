use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use digest::{typenum::Unsigned, OutputSizeUser};
use ecdsa::{
    elliptic_curve::{array::ArraySize, CurveArithmetic},
    hazmat::DigestAlgorithm,
    EcdsaCurve, PrimeCurve, SignatureSize,
};
use signature::{hazmat::PrehashSigner, Keypair};

use crate::{
    adapter::PublicKey as HPublicKey,
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::{ensure_eq, Result},
    packet::{PubKeyInner, PublicKey},
    types::{
        EcdsaPublicParams, Fingerprint, KeyDetails, KeyId, KeyVersion, Mpi, Password,
        PublicKeyTrait, PublicParams, SecretKeyTrait, SignatureBytes,
    },
};

impl<C> HPublicKey for ecdsa::VerifyingKey<C>
where
    Self: PgpEcdsaPublicKey,
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
{
    const PGP_ALGORITHM: PublicKeyAlgorithm = PublicKeyAlgorithm::ECDSA;

    fn pgp_parameters(&self) -> PublicParams {
        let key = self.ecdsa_public_key();
        PublicParams::ECDSA(key)
    }
}

/// Encoding for an ecdsa public key
pub trait PgpEcdsaPublicKey {
    /// public key parameter for a given public key
    fn ecdsa_public_key(&self) -> EcdsaPublicParams;
}

impl PgpEcdsaPublicKey for p256::ecdsa::VerifyingKey {
    fn ecdsa_public_key(&self) -> EcdsaPublicParams {
        let key = self.into();
        EcdsaPublicParams::P256 { key }
    }
}

/// [`signature::Signer`] backed signer for PGP.
#[derive(derive_more::Debug)]
#[debug("EcdsaSigner({public_key:?})")]
pub struct EcdsaSigner<T, C> {
    inner: T,
    public_key: PublicKey,
    _signature: PhantomData<C>,
}

impl<C, T> EcdsaSigner<T, C>
where
    T: Keypair,
    T::VerifyingKey: HPublicKey,
{
    /// Create a new signer with a given public key
    pub fn new(inner: T, version: KeyVersion, created_at: DateTime<Utc>) -> Result<Self> {
        let public_key = PubKeyInner::new(
            version,
            <T as Keypair>::VerifyingKey::PGP_ALGORITHM,
            created_at,
            None,
            inner.verifying_key().pgp_parameters(),
        )?;
        let public_key = PublicKey::from_inner(public_key)?;

        Ok(Self {
            inner,
            public_key,
            _signature: PhantomData,
        })
    }
}

impl<C, T> Keypair for EcdsaSigner<T, C>
where
    T: Keypair,
{
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl<C, T> EcdsaSigner<T, C>
where
    C: PrimeCurve + DigestAlgorithm,
    SignatureSize<C>: ArraySize,
    T: PrehashSigner<ecdsa::Signature<C>>,
    C::Digest: KnownDigest,
{
    fn sign_prehash(&self, hash: HashAlgorithm, prehash: &[u8]) -> Result<Vec<Vec<u8>>> {
        ensure_eq!(
            hash,
            C::Digest::HASH_ALGORITHM,
            "signer only supports {}",
            C::Digest::HASH_ALGORITHM
        );
        ensure_eq!(
            prehash.len(),
            <C::Digest as OutputSizeUser>::OutputSize::USIZE,
            "Prehashed digest length mismatch, expected {}",
            <C::Digest as OutputSizeUser>::OutputSize::USIZE
        );

        let signature = self.inner.sign_prehash(prehash)?;
        let (r, s) = signature.split_bytes();
        Ok(vec![r.to_vec(), s.to_vec()])
    }
}

impl<C, T> SecretKeyTrait for EcdsaSigner<T, C>
where
    C: PrimeCurve + DigestAlgorithm,
    SignatureSize<C>: ArraySize,
    T: PrehashSigner<ecdsa::Signature<C>>,
    C::Digest: KnownDigest,
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
        let mpis = sig.iter().map(|v| Mpi::from_slice(&v[..])).collect();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        C::Digest::HASH_ALGORITHM
    }
}

impl<C, T> KeyDetails for EcdsaSigner<T, C> {
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

impl<C, T> PublicKeyTrait for EcdsaSigner<T, C> {
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
