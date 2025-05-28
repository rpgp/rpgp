use zeroize::Zeroize;

use crate::{
    ser::Serialize,
    types::{ElgamalPublicParams, Mpi},
};

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
    fn to_mpi(&self) -> Mpi {
        Mpi::from_slice(&self.x)
    }

    pub(crate) fn try_from_mpi(pub_params: ElgamalPublicParams, x: Mpi) -> Self {
        Self {
            x: x.as_ref().to_vec(),
            public: pub_params,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.x
    }
}

impl From<&SecretKey> for ElgamalPublicParams {
    fn from(value: &SecretKey) -> Self {
        value.public.clone()
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        let x = self.to_mpi();
        x.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        let x = self.to_mpi();
        x.write_len()
    }
}
