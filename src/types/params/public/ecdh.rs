use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;

use crate::{
    crypto::{
        ecc_curve::{ecc_curve_from_oid, ECCCurve},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure_eq, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Mpi,
};

/// ECDH KDF type
/// See <https://datatracker.ietf.org/doc/html/draft-wussler-openpgp-forwarding#name-iana-considerations>
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdhKdfType {
    /// 0x01: "Native fingerprint KDF"
    Native,

    /// 0xFF: "Replaced fingerprint KDF"
    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    Replaced {
        /// "Forwardee key" fingerprint, see
        /// <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-generating-the-forwardee-ke>
        replacement_fingerprint: [u8; 20],
    },
}

impl From<EcdhKdfType> for u8 {
    fn from(value: EcdhKdfType) -> Self {
        match value {
            EcdhKdfType::Native => 0x01,
            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            EcdhKdfType::Replaced { .. } => 0xff,
        }
    }
}

impl EcdhKdfType {
    /// Length the KDF parameter block, in bytes
    const fn param_len(&self) -> u8 {
        match self {
            Self::Native => 0x03,
            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            Self::Replaced { .. } => 0x17,
        }
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdhPublicParams {
    /// ECDH public parameters for a curve that we know uses Mpi representation
    Curve25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_curve25519_gen()"))]
        p: x25519_dalek::PublicKey,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
        ecdh_kdf_type: EcdhKdfType,
    },
    P256 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p256_gen()"))]
        p: elliptic_curve::PublicKey<p256::NistP256>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p384_gen()"))]
        p: elliptic_curve::PublicKey<p384::NistP384>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p521_gen()"))]
        p: elliptic_curve::PublicKey<p521::NistP521>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    #[cfg_attr(test, proptest(skip))]
    Brainpool256 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    #[cfg_attr(test, proptest(skip))]
    Brainpool384 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    #[cfg_attr(test, proptest(skip))]
    Brainpool512 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// Public parameters for a curve that we don't know about (which might not use Mpi representation).
    #[cfg_attr(test, proptest(skip))]
    Unsupported {
        curve: ECCCurve,
        #[debug("{}", hex::encode(opaque))]
        opaque: Bytes,
    },
}

impl Serialize for EcdhPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = self.curve().oid();
        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        let tags = match self {
            Self::Curve25519 {
                p,
                hash,
                alg_sym,
                ecdh_kdf_type,
            } => {
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                mpi.to_writer(writer)?;
                Some((hash, alg_sym, ecdh_kdf_type))
            }
            Self::P256 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::P384 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::P521 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Brainpool256 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Brainpool384 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Brainpool512 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Unsupported { opaque, .. } => {
                writer.write_all(opaque)?;
                None
            }
        };

        if let Some((hash, alg_sym, ecdh_kdf_type)) = tags {
            writer.write_u8(ecdh_kdf_type.param_len())?;
            writer.write_u8((*ecdh_kdf_type).into())?;

            writer.write_u8((*hash).into())?;
            writer.write_u8((*alg_sym).into())?;

            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            if let EcdhKdfType::Replaced {
                replacement_fingerprint,
            } = ecdh_kdf_type
            {
                writer.write_all(&replacement_fingerprint[..])?; // 20 byte v4 fingerprint
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1; // oid len

        match self {
            Self::Curve25519 {
                p,
                #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                ecdh_kdf_type,
                ..
            } => {
                sum += self.curve().oid().len();
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                sum += mpi.write_len();

                // https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-generating-the-forwardee-ke
                #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                if matches![ecdh_kdf_type, EcdhKdfType::Replaced { .. }] {
                    sum += 20
                }
            }
            Self::P256 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P384 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P521 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Brainpool256 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Brainpool384 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Brainpool512 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Unsupported { curve, opaque, .. } => {
                let oid = curve.oid();
                sum += oid.len();
                sum += opaque.len();
            }
        };

        if !matches!(self, Self::Unsupported { .. }) {
            // fields and tags
            sum += 1 + 1 + 1 + 1;
        }
        sum
    }
}

impl EcdhPublicParams {
    /// Is this key based on a curve that we know how to parse?
    ///
    /// Unsupported curves are modeled as [`Self::Unsupported`].
    /// Key packets that use such curves are handled as opaque blobs.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    /// Get the `ECCCurve` that this key is based on
    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519 { .. } => ECCCurve::Curve25519,
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
            Self::Brainpool256 { .. } => ECCCurve::BrainpoolP256r1,
            Self::Brainpool384 { .. } => ECCCurve::BrainpoolP384r1,
            Self::Brainpool512 { .. } => ECCCurve::BrainpoolP512r1,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ecd>
    pub fn try_from_reader<B: BufRead>(mut i: B, len: Option<usize>) -> Result<Self> {
        // a one-octet size of the following field
        // octets representing a curve OID
        let curve_len = i.read_u8()?;
        let curve_raw = i.take_bytes(curve_len.into())?;
        let curve = ecc_curve_from_oid(&curve_raw).ok_or_else(|| format_err!("invalid curve"))?;

        match curve {
            ECCCurve::Curve25519
            | ECCCurve::P256
            | ECCCurve::P384
            | ECCCurve::P521
            | ECCCurve::BrainpoolP256r1
            | ECCCurve::BrainpoolP384r1
            | ECCCurve::BrainpoolP512r1 => {
                // MPI of an EC point representing a public key
                let p = Mpi::try_from_reader(&mut i)?;

                // a one-octet size of the following fields
                let len_param = i.read_u8()?;

                // a one-octet value for the "KDF type".
                // defaults to 0x01, as per RFC 9580.
                // 0xff is used for "forwardee keys", see
                // <https://datatracker.ietf.org/doc/html/draft-wussler-openpgp-forwarding#name-generating-the-forwardee-ke>
                let kdf_type = i.read_u8()?;

                // a one-octet hash function ID used with a KDF
                let hash = i.read_u8().map(HashAlgorithm::from)?;

                // a one-octet algorithm ID for the symmetric algorithm used to wrap
                // the symmetric key used for the message encryption
                let alg_sym = i.read_u8().map(SymmetricKeyAlgorithm::from)?;

                let ecdh_kdf_type = match kdf_type {
                    0x01 => EcdhKdfType::Native,

                    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                    0xff => {
                        crate::errors::ensure!(
                            curve == ECCCurve::Curve25519,
                            "unexpected curve for forwardee key {}",
                            curve
                        );

                        EcdhKdfType::Replaced {
                            replacement_fingerprint: i.read_array()?,
                        }
                    }

                    typ => bail!("unexpected ECDH KDF type {}", typ),
                };

                // now we can sanity-check len_param against ecdh_kdf_type
                ensure_eq!(
                    len_param,
                    ecdh_kdf_type.param_len(),
                    "unexpected length {} for kdf type {}",
                    len_param,
                    kdf_type
                );

                let params = Self::try_from_mpi(p, curve, hash, alg_sym, ecdh_kdf_type)?;
                Ok(params)
            }
            _ => {
                let data = if let Some(pub_len) = len {
                    i.take_bytes(pub_len)?.freeze()
                } else {
                    i.rest()?.freeze()
                };
                Ok(EcdhPublicParams::Unsupported {
                    curve,
                    opaque: data,
                })
            }
        }
    }

    fn try_from_mpi(
        p: Mpi,
        curve: ECCCurve,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
        ecdh_kdf_type: EcdhKdfType,
    ) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519 => {
                ensure_eq!(p.len(), 33, "invalid public key length");
                // public part of the ephemeral key (removes 0x40 prefix)
                let public_key = &p.as_ref()[1..];

                // create montgomery point
                let mut public_key_arr = [0u8; 32];
                public_key_arr[..].copy_from_slice(public_key);

                let p = x25519_dalek::PublicKey::from(public_key_arr);
                Ok(EcdhPublicParams::Curve25519 {
                    p,
                    hash,
                    alg_sym,
                    ecdh_kdf_type,
                })
            }
            ECCCurve::P256 => {
                let p = p256::PublicKey::from_sec1_bytes(p.as_ref())?;
                Ok(EcdhPublicParams::P256 { p, hash, alg_sym })
            }
            ECCCurve::P384 => {
                let p = p384::PublicKey::from_sec1_bytes(p.as_ref())?;
                Ok(EcdhPublicParams::P384 { p, hash, alg_sym })
            }
            ECCCurve::P521 => {
                let p = p521::PublicKey::from_sec1_bytes(p.as_ref())?;
                Ok(EcdhPublicParams::P521 { p, hash, alg_sym })
            }
            ECCCurve::BrainpoolP256r1 => Ok(EcdhPublicParams::Brainpool256 { p, hash, alg_sym }),
            ECCCurve::BrainpoolP384r1 => Ok(EcdhPublicParams::Brainpool384 { p, hash, alg_sym }),
            ECCCurve::BrainpoolP512r1 => Ok(EcdhPublicParams::Brainpool512 { p, hash, alg_sym }),
            _ => bail!("unexpected ecdh curve: {:?}", curve),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;

    proptest::prop_compose! {
        pub fn ecdh_curve25519_gen()(seed: u64) -> x25519_dalek::PublicKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            let mut secret_key_bytes = [0u8; ECCCurve::Curve25519.secret_key_length()];
            rng.fill_bytes(&mut secret_key_bytes);

            let secret = x25519_dalek::StaticSecret::from(secret_key_bytes);
            x25519_dalek::PublicKey::from(&secret)
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p256_gen()(seed: u64) -> elliptic_curve::PublicKey<p256::NistP256> {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p384_gen()(seed: u64) -> elliptic_curve::PublicKey<p384::NistP384> {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p521_gen()(seed: u64) -> elliptic_curve::PublicKey<p521::NistP521> {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rng).public_key()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = EcdhPublicParams::try_from_reader(&mut &buf[..], None)?;
            prop_assert_eq!(params, new_params);
        }
    }
}
