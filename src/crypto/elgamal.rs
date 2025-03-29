use zeroize::Zeroize;

use crate::types::{ElgamalPublicParams, Mpi};

/// Secret key for Elgamal.
#[derive(Clone, PartialEq, Zeroize, derive_more::Debug, Eq)]
pub struct SecretKey {
    /// MPI of Elgamal secret exponent x.
    // stored as vec to be zeroizable
    #[debug("..")]
    x: Vec<u8>,
    #[zeroize(skip)]
    public: ElgamalPublicParams,
}

impl SecretKey {
    pub(crate) fn as_mpi(&self) -> Mpi {
        Mpi::from_slice(&self.x)
    }

    pub(crate) fn try_from_mpi(pub_params: ElgamalPublicParams, x: Mpi) -> Self {
        Self {
            x: x.as_ref().to_vec(),
            public: pub_params,
        }
    }
}

impl From<&SecretKey> for ElgamalPublicParams {
    fn from(value: &SecretKey) -> Self {
        value.public.clone()
    }
}
