use std::io;

use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::Mpi;

#[cfg(test)]
pub use tests::public_params_gen;

mod dsa;
mod ecdh;
mod ecdsa;
mod eddsa_legacy;
mod rsa;

pub use self::dsa::DsaPublicParams;
pub use self::ecdh::EcdhPublicParams;
pub use self::ecdsa::EcdsaPublicParams;
pub use self::eddsa_legacy::EddsaLegacyPublicParams;
pub use self::rsa::RsaPublicParams;

/// Represent the public parameters for the different algorithms.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum PublicParams {
    RSA(RsaPublicParams),
    DSA(DsaPublicParams),
    ECDSA(EcdsaPublicParams),
    ECDH(EcdhPublicParams),
    Elgamal {
        p: Mpi,
        g: Mpi,
        y: Mpi,
    },
    EdDSALegacy(EddsaLegacyPublicParams),
    Ed25519 {
        public: ed25519_dalek::VerifyingKey,
    },
    X25519 {
        public: x25519_dalek::PublicKey,
    },
    #[cfg(feature = "unstable-curve448")]
    // Can't store the x448 key because it doesn't even implement `Debug`..
    X448 {
        public: [u8; 56],
    },
    Unknown {
        data: Vec<u8>,
    },
}

impl Serialize for PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicParams::RSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::DSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::ECDSA(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::ECDH(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => {
                p.to_writer(writer)?;
                g.to_writer(writer)?;
                y.to_writer(writer)?;
            }
            PublicParams::EdDSALegacy(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Ed25519 { ref public } => {
                writer.write_all(&public.as_bytes()[..])?;
            }
            PublicParams::X25519 { ref public } => {
                writer.write_all(public.as_bytes())?;
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448 { ref public } => {
                writer.write_all(&public[..])?;
            }
            PublicParams::Unknown { ref data } => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            PublicParams::RSA(params) => {
                sum += params.write_len();
            }
            PublicParams::DSA(params) => {
                sum += params.write_len();
            }
            PublicParams::ECDSA(params) => {
                sum += params.write_len();
            }
            PublicParams::ECDH(params) => {
                sum += params.write_len();
            }
            PublicParams::Elgamal {
                ref p,
                ref g,
                ref y,
            } => {
                sum += p.write_len();
                sum += g.write_len();
                sum += y.write_len();
            }
            PublicParams::EdDSALegacy(params) => {
                sum += params.write_len();
            }
            PublicParams::Ed25519 { ref public } => {
                sum += public.as_bytes().len();
            }
            PublicParams::X25519 { ref public } => {
                sum += public.as_bytes().len();
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448 { ref public } => {
                sum += public.len();
            }
            PublicParams::Unknown { ref data } => {
                sum += data.len();
            }
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::crypto::public_key::PublicKeyAlgorithm;

    proptest! {
        #[test]
        fn ecdh_params_write_len(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }
    }

    pub fn public_params_gen(
        params: PublicKeyAlgorithm,
    ) -> proptest::prelude::BoxedStrategy<PublicParams> {
        match params {
            PublicKeyAlgorithm::RSA => prop::arbitrary::any::<RsaPublicParams>()
                .prop_map(PublicParams::RSA)
                .boxed(),
            PublicKeyAlgorithm::DSA => prop::arbitrary::any::<DsaPublicParams>()
                .prop_map(PublicParams::DSA)
                .boxed(),
            PublicKeyAlgorithm::ECDSA => prop::arbitrary::any::<EcdsaPublicParams>()
                .prop_map(PublicParams::ECDSA)
                .boxed(),
            PublicKeyAlgorithm::ECDH => prop::arbitrary::any::<EcdhPublicParams>()
                .prop_map(PublicParams::ECDH)
                .boxed(),
            PublicKeyAlgorithm::Elgamal => prop::arbitrary::any::<(Mpi, Mpi, Mpi)>()
                .boxed()
                .prop_map(|(p, g, y)| PublicParams::Elgamal { p, g, y })
                .boxed(),
            PublicKeyAlgorithm::EdDSALegacy => prop::arbitrary::any::<EddsaLegacyPublicParams>()
                .prop_map(PublicParams::EdDSALegacy)
                .boxed(),
            PublicKeyAlgorithm::Ed25519 => eddsa_legacy::tests::ed25519_pub_gen()
                .prop_map(|public| PublicParams::Ed25519 { public })
                .boxed(),
            PublicKeyAlgorithm::X25519 => ecdh::tests::ecdh_curve25519_gen()
                .prop_map(|public| PublicParams::X25519 { public })
                .boxed(),
            #[cfg(feature = "unstable-curve448")]
            PublicKeyAlgorithm::X448 => prop::arbitrary::any::<[u8; 56]>()
                .prop_map(|public| PublicParams::X448 { public })
                .boxed(),
            _ => {
                unimplemented!("{:?}", params)
            }
        }
    }
}
