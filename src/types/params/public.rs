use std::io::{self, BufRead};

use bytes::Bytes;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{Error, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

mod dsa;
pub(crate) mod ecdh;
mod ecdsa;
mod ed25519;
mod ed448;
mod eddsa_legacy;
mod elgamal;
mod rsa;
mod x25519;
mod x448;

#[cfg(feature = "draft-pqc")]
mod ml_dsa65_ed25519;
#[cfg(feature = "draft-pqc")]
mod ml_dsa87_ed448;
#[cfg(feature = "draft-pqc")]
mod ml_kem1024_x448;
#[cfg(feature = "draft-pqc")]
mod ml_kem768_x25519;
#[cfg(feature = "draft-pqc")]
mod slh_dsa_shake128f;
#[cfg(feature = "draft-pqc")]
mod slh_dsa_shake128s;
#[cfg(feature = "draft-pqc")]
mod slh_dsa_shake256s;

pub use self::{
    dsa::DsaPublicParams, ecdh::EcdhPublicParams, ecdsa::EcdsaPublicParams,
    ed25519::Ed25519PublicParams, ed448::Ed448PublicParams, eddsa_legacy::EddsaLegacyPublicParams,
    elgamal::ElgamalPublicParams, rsa::RsaPublicParams, x25519::X25519PublicParams,
    x448::X448PublicParams,
};
#[cfg(feature = "draft-pqc")]
pub use self::{
    ml_dsa65_ed25519::MlDsa65Ed25519PublicParams, ml_dsa87_ed448::MlDsa87Ed448PublicParams,
    ml_kem1024_x448::MlKem1024X448PublicParams, ml_kem768_x25519::MlKem768X25519PublicParams,
    slh_dsa_shake128f::SlhDsaShake128fPublicParams, slh_dsa_shake128s::SlhDsaShake128sPublicParams,
    slh_dsa_shake256s::SlhDsaShake256sPublicParams,
};
use super::PlainSecretParams;

/// Represent the public parameters for the different algorithms.
#[derive(PartialEq, Eq, Clone, derive_more::Debug)]
pub enum PublicParams {
    RSA(RsaPublicParams),
    DSA(DsaPublicParams),
    ECDSA(EcdsaPublicParams),
    ECDH(EcdhPublicParams),
    Elgamal(ElgamalPublicParams),
    EdDSALegacy(EddsaLegacyPublicParams),
    Ed25519(Ed25519PublicParams),
    X25519(X25519PublicParams),
    X448(X448PublicParams),
    Ed448(Ed448PublicParams),
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519(MlKem768X25519PublicParams),
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448(MlKem1024X448PublicParams),
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519(MlDsa65Ed25519PublicParams),
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448(MlDsa87Ed448PublicParams),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s(SlhDsaShake128sPublicParams),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f(SlhDsaShake128fPublicParams),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s(SlhDsaShake256sPublicParams),
    Unknown {
        #[debug("{}", hex::encode(data))]
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
            PlainSecretParams::Ed25519(ref p) => Ok(Self::Ed25519(p.into())),
            PlainSecretParams::Ed25519Legacy(ref p) => Ok(Self::EdDSALegacy(p.into())),
            PlainSecretParams::X25519(ref p) => Ok(Self::X25519(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem768X25519(ref p) => Ok(Self::MlKem768X25519(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem1024X448(ref p) => Ok(Self::MlKem1024X448(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa65Ed25519(ref p) => Ok(Self::MlDsa65Ed25519(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa87Ed448(ref p) => Ok(Self::MlDsa87Ed448(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128s(ref p) => Ok(Self::SlhDsaShake128s(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128f(ref p) => Ok(Self::SlhDsaShake128f(p.into())),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake256s(ref p) => Ok(Self::SlhDsaShake256s(p.into())),
            PlainSecretParams::X448(ref p) => Ok(Self::X448(p.into())),
            PlainSecretParams::Ed448(ref p) => Ok(Self::Ed448(p.into())),
            PlainSecretParams::Unknown { pub_params, .. } => Ok(Self::Unknown {
                data: pub_params.clone(),
            }),
        }
    }
}

impl PublicParams {
    /// Parses the public parameters of key.
    pub fn try_from_reader<B: BufRead>(
        typ: PublicKeyAlgorithm,
        len: Option<usize>,
        i: B,
    ) -> Result<PublicParams> {
        match typ {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let params = RsaPublicParams::try_from_reader(i)?;
                Ok(PublicParams::RSA(params))
            }
            PublicKeyAlgorithm::DSA => {
                let params = DsaPublicParams::try_from_reader(i)?;
                Ok(PublicParams::DSA(params))
            }
            PublicKeyAlgorithm::ECDSA => {
                let params = EcdsaPublicParams::try_from_reader(i, len)?;
                Ok(PublicParams::ECDSA(params))
            }
            PublicKeyAlgorithm::ECDH => {
                let params = EcdhPublicParams::try_from_reader(i, len)?;
                Ok(PublicParams::ECDH(params))
            }
            PublicKeyAlgorithm::Elgamal => {
                let params = ElgamalPublicParams::try_from_reader(i, false)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::ElgamalEncrypt => {
                let params = ElgamalPublicParams::try_from_reader(i, true)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                let params = EddsaLegacyPublicParams::try_from_reader(i, len)?;
                Ok(PublicParams::EdDSALegacy(params))
            }
            PublicKeyAlgorithm::Ed25519 => {
                let params = Ed25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::Ed25519(params))
            }
            PublicKeyAlgorithm::X25519 => {
                let params = X25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::X25519(params))
            }
            PublicKeyAlgorithm::Ed448 => {
                let params = Ed448PublicParams::try_from_reader(i)?;
                Ok(PublicParams::Ed448(params))
            }
            PublicKeyAlgorithm::X448 => {
                let params = X448PublicParams::try_from_reader(i)?;
                Ok(PublicParams::X448(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlKem768X25519 => {
                let params = MlKem768X25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::MlKem768X25519(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlKem1024X448 => {
                let params = MlKem1024X448PublicParams::try_from_reader(i)?;
                Ok(PublicParams::MlKem1024X448(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlDsa65Ed25519 => {
                let params = MlDsa65Ed25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::MlDsa65Ed25519(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlDsa87Ed448 => {
                let params = MlDsa87Ed448PublicParams::try_from_reader(i)?;
                Ok(PublicParams::MlDsa87Ed448(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake128s => {
                let params = SlhDsaShake128sPublicParams::try_from_reader(i)?;
                Ok(PublicParams::SlhDsaShake128s(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake128f => {
                let params = SlhDsaShake128fPublicParams::try_from_reader(i)?;
                Ok(PublicParams::SlhDsaShake128f(params))
            }
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake256s => {
                let params = SlhDsaShake256sPublicParams::try_from_reader(i)?;
                Ok(PublicParams::SlhDsaShake256s(params))
            }
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
            PublicParams::RSA(_)
            | PublicParams::DSA(_)
            | PublicParams::EdDSALegacy(_)
            | PublicParams::Ed25519(_) => HashAlgorithm::Sha256,

            PublicParams::ECDSA(
                EcdsaPublicParams::P256 { .. }
                | EcdsaPublicParams::Secp256k1 { .. }
                | EcdsaPublicParams::Unsupported { .. },
            ) => HashAlgorithm::Sha256,
            PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => HashAlgorithm::Sha384,
            PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => HashAlgorithm::Sha512,

            PublicParams::Ed448(_) => HashAlgorithm::Sha512,

            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa65Ed25519(_) => HashAlgorithm::Sha256,
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa87Ed448(_) => HashAlgorithm::Sha512,
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128s(_) => HashAlgorithm::Sha256,
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128f(_) => HashAlgorithm::Sha256,
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake256s(_) => HashAlgorithm::Sha512,

            // Not actually signing capable
            PublicParams::Elgamal(_)
            | PublicParams::ECDH(_)
            | PublicParams::X25519(_)
            | PublicParams::X448(_)
            | PublicParams::Unknown { .. } => HashAlgorithm::Sha256,

            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem768X25519(_) | PublicParams::MlKem1024X448(_) => {
                HashAlgorithm::Sha256
            }
        }
    }
}

fn unknown<B: BufRead>(mut i: B, len: Option<usize>) -> Result<PublicParams> {
    if let Some(pub_len) = len {
        let data = i.take_bytes(pub_len)?.freeze();
        Ok(PublicParams::Unknown { data })
    } else {
        // consume the reset
        let data = i.rest()?.freeze();
        Ok(PublicParams::Unknown { data })
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
            PublicParams::Ed448(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::X25519(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem768X25519(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem1024X448(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::X448(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa65Ed25519(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa87Ed448(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128s(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128f(params) => {
                params.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake256s(params) => {
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
            PublicParams::Ed448(params) => {
                sum += params.write_len();
            }
            PublicParams::X25519(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem768X25519(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem1024X448(params) => {
                sum += params.write_len();
            }
            PublicParams::X448(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa65Ed25519(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlDsa87Ed448(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128s(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake128f(params) => {
                sum += params.write_len();
            }
            #[cfg(feature = "draft-pqc")]
            PublicParams::SlhDsaShake256s(params) => {
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
    use proptest::prelude::*;

    use super::*;
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
            let new_params = PublicParams::try_from_reader(alg, None, &mut &buf[..])?;
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
                PublicKeyAlgorithm::X448 => any::<X448PublicParams>()
                    .prop_map(PublicParams::X448)
                    .boxed(),
                PublicKeyAlgorithm::Ed448 => any::<Ed448PublicParams>()
                    .prop_map(PublicParams::Ed448)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlKem768X25519 => any::<MlKem768X25519PublicParams>()
                    .prop_map(PublicParams::MlKem768X25519)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlKem1024X448 => any::<MlKem1024X448PublicParams>()
                    .prop_map(PublicParams::MlKem1024X448)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlDsa65Ed25519 => any::<MlDsa65Ed25519PublicParams>()
                    .prop_map(PublicParams::MlDsa65Ed25519)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlDsa87Ed448 => any::<MlDsa87Ed448PublicParams>()
                    .prop_map(PublicParams::MlDsa87Ed448)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake128s => any::<SlhDsaShake128sPublicParams>()
                    .prop_map(PublicParams::SlhDsaShake128s)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake128f => any::<SlhDsaShake128fPublicParams>()
                    .prop_map(PublicParams::SlhDsaShake128f)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake256s => any::<SlhDsaShake256sPublicParams>()
                    .prop_map(PublicParams::SlhDsaShake256s)
                    .boxed(),
                _ => {
                    unimplemented!("{:?}", args)
                }
            }
        }
    }
}
