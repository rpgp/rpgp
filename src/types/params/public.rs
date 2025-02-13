use std::io;

use bytes::{Buf, Bytes};

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::parsing::BufParsing;
use crate::ser::Serialize;

mod dsa;
mod ecdh;
mod ecdsa;
mod ed25519;
mod eddsa_legacy;
mod elgamal;
mod rsa;
mod x25519;
#[cfg(feature = "unstable-curve448")]
mod x448;

pub use self::dsa::DsaPublicParams;
pub use self::ecdh::EcdhPublicParams;
pub use self::ecdsa::EcdsaPublicParams;
pub use self::ed25519::Ed25519PublicParams;
pub use self::eddsa_legacy::EddsaLegacyPublicParams;
pub use self::elgamal::ElgamalPublicParams;
pub use self::rsa::RsaPublicParams;
pub use self::x25519::X25519PublicParams;
#[cfg(feature = "unstable-curve448")]
pub use self::x448::X448PublicParams;

use super::PlainSecretParams;

/// Represent the public parameters for the different algorithms.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum PublicParams {
    RSA(RsaPublicParams),
    DSA(DsaPublicParams),
    ECDSA(EcdsaPublicParams),
    ECDH(EcdhPublicParams),
    Elgamal(ElgamalPublicParams),
    EdDSALegacy(EddsaLegacyPublicParams),
    Ed25519(Ed25519PublicParams),
    X25519(X25519PublicParams),
    #[cfg(feature = "unstable-curve448")]
    X448(X448PublicParams),
    Unknown {
        data: Bytes,
    },
}

impl TryFrom<&PlainSecretParams> for PublicParams {
    type Error = Error;

    fn try_from(secret: &PlainSecretParams) -> Result<Self, Self::Error> {
        match secret {
            PlainSecretParams::RSA(ref p) => Ok(Self::RSA(p.into())),
            PlainSecretParams::DSA(ref p) => Ok(Self::DSA(p.into())),
            PlainSecretParams::ECDSA(ref p) => p.try_into().map(Self::ECDSA),
            PlainSecretParams::ECDH(ref p) => Ok(Self::ECDH(p.into())),
            PlainSecretParams::Elgamal(ref p) => Ok(Self::Elgamal(p.into())),
            PlainSecretParams::EdDSA(ref p) => Ok(Self::Ed25519(p.into())),
            PlainSecretParams::EdDSALegacy(ref p) => Ok(Self::EdDSALegacy(p.into())),
            PlainSecretParams::X25519(ref p) => Ok(Self::X25519(p.into())),
            #[cfg(feature = "unstable-curve448")]
            PlainSecretParams::X448(ref p) => Ok(Self::X448(p.into())),
        }
    }
}

impl PublicParams {
    /// Parses the public parameters of key.
    pub fn try_from_buf<B: Buf>(
        typ: PublicKeyAlgorithm,
        len: Option<usize>,
        i: B,
    ) -> Result<PublicParams> {
        match typ {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let params = RsaPublicParams::try_from_buf(i)?;
                Ok(PublicParams::RSA(params))
            }
            PublicKeyAlgorithm::DSA => {
                let params = DsaPublicParams::try_from_buf(i)?;
                Ok(PublicParams::DSA(params))
            }
            PublicKeyAlgorithm::ECDSA => {
                let params = EcdsaPublicParams::try_from_buf(i)?;
                Ok(PublicParams::ECDSA(params))
            }
            PublicKeyAlgorithm::ECDH => {
                let params = EcdhPublicParams::try_from_buf(i, len)?;
                Ok(PublicParams::ECDH(params))
            }
            PublicKeyAlgorithm::Elgamal => {
                let params = ElgamalPublicParams::try_from_buf(i, false)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::ElgamalEncrypt => {
                let params = ElgamalPublicParams::try_from_buf(i, true)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                let params = EddsaLegacyPublicParams::try_from_buf(i)?;
                Ok(PublicParams::EdDSALegacy(params))
            }
            PublicKeyAlgorithm::Ed25519 => {
                let params = Ed25519PublicParams::try_from_buf(i)?;
                Ok(PublicParams::Ed25519(params))
            }
            PublicKeyAlgorithm::X25519 => {
                let params = X25519PublicParams::try_from_buf(i)?;
                Ok(PublicParams::X25519(params))
            }
            PublicKeyAlgorithm::Ed448 => unknown(i, len), // FIXME: implement later
            #[cfg(feature = "unstable-curve448")]
            PublicKeyAlgorithm::X448 => {
                let params = X448PublicParams::try_from_buf(i)?;
                Ok(PublicParams::X448(params))
            }
            #[cfg(not(feature = "unstable-curve448"))]
            PublicKeyAlgorithm::X448 => unknown(i, len),

            PublicKeyAlgorithm::DiffieHellman
            | PublicKeyAlgorithm::Private100
            | PublicKeyAlgorithm::Private101
            | PublicKeyAlgorithm::Private102
            | PublicKeyAlgorithm::Private103
            | PublicKeyAlgorithm::Private104
            | PublicKeyAlgorithm::Private105
            | PublicKeyAlgorithm::Private106
            | PublicKeyAlgorithm::Private107
            | PublicKeyAlgorithm::Private108
            | PublicKeyAlgorithm::Private109
            | PublicKeyAlgorithm::Private110
            | PublicKeyAlgorithm::Unknown(_) => unknown(i, len),
        }
    }

    /// The suggested hash algorithm to calculate the signature hash digest with, when using this
    /// key as a signer
    pub fn hash_alg(&self) -> HashAlgorithm {
        match self {
            PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => HashAlgorithm::SHA2_384,
            PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => HashAlgorithm::SHA2_512,
            _ => HashAlgorithm::default(),
        }
    }
}

fn unknown<B: Buf>(mut i: B, len: Option<usize>) -> Result<PublicParams> {
    if let Some(pub_len) = len {
        let data = i.read_take(pub_len)?;
        Ok(PublicParams::Unknown { data })
    } else {
        // we don't know how many bytes to consume
        Ok(PublicParams::Unknown {
            data: Bytes::default(),
        })
    }
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
            PublicParams::Elgamal(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::EdDSALegacy(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Ed25519(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::X25519(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448(params) => {
                params.to_writer(writer)?;
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
            PublicParams::Elgamal(params) => {
                sum += params.write_len();
            }
            PublicParams::EdDSALegacy(params) => {
                sum += params.write_len();
            }
            PublicParams::Ed25519(params) => {
                sum += params.write_len();
            }
            PublicParams::X25519(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "unstable-curve448")]
            PublicParams::X448(params) => {
                sum += params.write_len();
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
        #[ignore]
        fn params_write_len(params: PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        #[ignore]
        fn params_roundtrip(
            (alg, params) in any::<PublicKeyAlgorithm>().prop_flat_map(|alg| {
                (Just(alg), any_with::<PublicParams>(alg))
            })
        ) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = PublicParams::try_from_buf(alg, None, &mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }

    impl Default for PublicKeyAlgorithm {
        fn default() -> Self {
            unreachable!("must not be used, only here for testing");
        }
    }

    impl Arbitrary for PublicParams {
        type Parameters = PublicKeyAlgorithm;
        type Strategy = BoxedStrategy<PublicParams>;

        fn arbitrary() -> Self::Strategy {
            any::<PublicKeyAlgorithm>()
                .prop_flat_map(Self::arbitrary_with)
                .boxed()
        }

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            match args {
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSAEncrypt
                | PublicKeyAlgorithm::RSASign => {
                    any::<RsaPublicParams>().prop_map(PublicParams::RSA).boxed()
                }
                PublicKeyAlgorithm::DSA => {
                    any::<DsaPublicParams>().prop_map(PublicParams::DSA).boxed()
                }
                PublicKeyAlgorithm::ECDSA => any::<EcdsaPublicParams>()
                    .prop_map(PublicParams::ECDSA)
                    .boxed(),
                PublicKeyAlgorithm::ECDH => any::<EcdhPublicParams>()
                    .prop_map(PublicParams::ECDH)
                    .boxed(),
                PublicKeyAlgorithm::Elgamal => any::<ElgamalPublicParams>()
                    .boxed()
                    .prop_map(PublicParams::Elgamal)
                    .boxed(),
                PublicKeyAlgorithm::EdDSALegacy => any::<EddsaLegacyPublicParams>()
                    .prop_map(PublicParams::EdDSALegacy)
                    .boxed(),
                PublicKeyAlgorithm::Ed25519 => any::<Ed25519PublicParams>()
                    .prop_map(PublicParams::Ed25519)
                    .boxed(),
                PublicKeyAlgorithm::X25519 => any::<X25519PublicParams>()
                    .prop_map(PublicParams::X25519)
                    .boxed(),
                #[cfg(feature = "unstable-curve448")]
                PublicKeyAlgorithm::X448 => any::<X448PublicParams>()
                    .prop_map(PublicParams::X448)
                    .boxed(),
                _ => {
                    unimplemented!("{:?}", args)
                }
            }
        }
    }
}
