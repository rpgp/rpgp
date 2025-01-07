use std::io;

use nom::bytes::streaming::take;

use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, IResult, Result};
use crate::ser::Serialize;
use crate::types::SecretKeyRepr;

mod dsa;
mod ecdh;
mod ecdsa;
mod ed25519;
mod eddsa_legacy;
mod elgamal;
mod rsa;
mod x25519;

pub use self::dsa::DsaPublicParams;
pub use self::ecdh::EcdhPublicParams;
pub use self::ecdsa::EcdsaPublicParams;
pub use self::ed25519::Ed25519PublicParams;
pub use self::eddsa_legacy::EddsaLegacyPublicParams;
pub use self::elgamal::ElgamalPublicParams;
pub use self::rsa::RsaPublicParams;
pub use self::x25519::X25519PublicParams;

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
    // Can't store the x448 key because it doesn't even implement `Debug`..
    X448 {
        public: [u8; 56],
    },
    Unknown {
        data: Vec<u8>,
    },
}
impl TryFrom<&SecretKeyRepr> for PublicParams {
    type Error = Error;

    fn try_from(secret: &SecretKeyRepr) -> Result<Self, Self::Error> {
        match secret {
            SecretKeyRepr::RSA(ref p) => Ok(Self::RSA(p.into())),
            SecretKeyRepr::DSA(ref p) => Ok(Self::DSA(p.into())),
            SecretKeyRepr::ECDSA(ref p) => p.try_into().map(Self::ECDSA),
            SecretKeyRepr::ECDH(ref p) => Ok(Self::ECDH(p.into())),
            SecretKeyRepr::EdDSA(ref p) => Ok(Self::Ed25519(p.into())),
            SecretKeyRepr::EdDSALegacy(ref p) => Ok(Self::EdDSALegacy(p.into())),
            SecretKeyRepr::X25519(ref p) => Ok(Self::X25519(p.into())),
            #[cfg(feature = "unstable-curve448")]
            SecretKeyRepr::X448(ref p) => {
                let secret = x448::Secret::from(p.secret); // does clamping
                let public = *x448::PublicKey::from(&secret).as_bytes();

                Ok(Self::X448 { public })
            }
        }
    }
}

impl PublicParams {
    /// Parses the public parameters of key.
    pub fn try_from_slice(
        typ: PublicKeyAlgorithm,
        len: Option<usize>,
    ) -> impl Fn(&[u8]) -> IResult<&[u8], PublicParams> {
        move |i: &[u8]| match typ {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (i, params) = RsaPublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::RSA(params)))
            }
            PublicKeyAlgorithm::DSA => {
                let (i, params) = DsaPublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::DSA(params)))
            }
            PublicKeyAlgorithm::ECDSA => {
                let (i, params) = EcdsaPublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::ECDSA(params)))
            }
            PublicKeyAlgorithm::ECDH => {
                let (i, params) = EcdhPublicParams::try_from_slice(i, len)?;
                Ok((i, PublicParams::ECDH(params)))
            }
            PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => {
                let (i, params) = ElgamalPublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::Elgamal(params)))
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                let (i, params) = EddsaLegacyPublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::EdDSALegacy(params)))
            }
            PublicKeyAlgorithm::Ed25519 => {
                let (i, params) = Ed25519PublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::Ed25519(params)))
            }
            PublicKeyAlgorithm::X25519 => {
                let (i, params) = X25519PublicParams::try_from_slice(i)?;
                Ok((i, PublicParams::X25519(params)))
            }
            PublicKeyAlgorithm::Ed448 => unknown(i, len), // FIXME: implement later
            #[cfg(feature = "unstable-curve448")]
            PublicKeyAlgorithm::X448 => x448(i),
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
}

/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4>
#[cfg(feature = "unstable-curve448")]
fn x448(i: &[u8]) -> IResult<&[u8], PublicParams> {
    // 56 bytes of public key
    let (i, p) = take(56u8)(i)?;
    let params = PublicParams::X448 {
        public: p.try_into().expect("we took 56 bytes"),
    };

    Ok((i, params))
}

fn unknown(i: &[u8], len: Option<usize>) -> IResult<&[u8], PublicParams> {
    if let Some(pub_len) = len {
        let (i, data) = take(pub_len)(i)?;
        Ok((
            i,
            PublicParams::Unknown {
                data: data.to_vec(),
            },
        ))
    } else {
        // we don't know how many bytes to consume
        Ok((i, PublicParams::Unknown { data: vec![] }))
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
            let (i, new_params) = PublicParams::try_from_slice(alg, None)(&buf)?;
            assert!(i.is_empty());
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
                PublicKeyAlgorithm::X448 => any::<[u8; 56]>()
                    .prop_map(|public| PublicParams::X448 { public })
                    .boxed(),
                _ => {
                    unimplemented!("{:?}", args)
                }
            }
        }
    }
}
