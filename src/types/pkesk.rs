use std::io::BufRead;

use byteorder::WriteBytesExt;
use bytes::Bytes;
#[cfg(test)]
use proptest::prelude::*;

use super::Mpi;
use crate::{
    crypto::{public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{unsupported_err, InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

/// Values comprising a Public Key Encrypted Session Key
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkeskBytes {
    Rsa {
        mpi: Mpi,
    },
    Elgamal {
        first: Mpi,
        second: Mpi,
    },
    Ecdh {
        public_point: Mpi,
        encrypted_session_key: Bytes,
    },
    X25519 {
        /// Ephemeral X25519 public key (32 bytes).
        ephemeral: [u8; 32],
        /// Encrypted and wrapped session key.
        session_key: Bytes,
        /// Set for v3 PKESK only (the sym_alg is not encrypted with the session key for X25519)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    X448 {
        /// Ephemeral X448 public key (56 bytes).
        ephemeral: [u8; 56],
        /// Encrypted and wrapped session key.
        session_key: Bytes,
        /// Set for v3 PKESK only (the sym_alg is not encrypted with the session key for X448)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    Other,
}

impl PkeskBytes {
    pub fn try_from_reader<B: BufRead>(
        alg: &PublicKeyAlgorithm,
        version: u8,
        mut i: B,
    ) -> Result<Self> {
        match alg {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::RSAEncrypt => {
                let mpi = Mpi::try_from_reader(&mut i)?;
                Ok(PkeskBytes::Rsa { mpi })
            }
            PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalEncrypt => {
                let first = Mpi::try_from_reader(&mut i)?;
                let second = Mpi::try_from_reader(&mut i)?;
                Ok(PkeskBytes::Elgamal { first, second })
            }
            PublicKeyAlgorithm::ECDSA
            | PublicKeyAlgorithm::DSA
            | PublicKeyAlgorithm::DiffieHellman => Ok(PkeskBytes::Other),
            PublicKeyAlgorithm::ECDH => {
                let public_point = Mpi::try_from_reader(&mut i)?;
                let session_key_len = i.read_u8()?;
                let session_key = i.take_bytes(session_key_len.into())?.freeze();

                Ok(PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key: session_key,
                })
            }
            PublicKeyAlgorithm::X25519 => {
                // 32 octets representing an ephemeral X25519 public key.
                let ephemeral_public = i.read_array::<32>()?;

                // A one-octet size of the following fields.
                let len = i.read_u8()?;
                if len == 0 {
                    return Err(InvalidInputSnafu.build());
                }

                // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
                let sym_alg = if version == 3 {
                    let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
                    Some(alg)
                } else {
                    None
                };

                let skey_len = if version == 3 { len - 1 } else { len };

                // The encrypted session key.
                let esk = i.take_bytes(skey_len.into())?.freeze();

                Ok(PkeskBytes::X25519 {
                    ephemeral: ephemeral_public,
                    sym_alg,
                    session_key: esk,
                })
            }
            PublicKeyAlgorithm::X448 => {
                // 56 octets representing an ephemeral X448 public key.
                let ephemeral_public = i.read_array::<56>()?;

                // A one-octet size of the following fields.
                let len = i.read_u8()?;
                if len == 0 {
                    return Err(InvalidInputSnafu.build());
                }

                // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
                let sym_alg = if version == 3 {
                    let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
                    Some(alg)
                } else {
                    None
                };

                let skey_len = if version == 3 { len - 1 } else { len };

                // The encrypted session key.
                let session_key = i.take_bytes(skey_len.into())?.freeze();

                Ok(PkeskBytes::X448 {
                    ephemeral: ephemeral_public,
                    sym_alg,
                    session_key,
                })
            }
            PublicKeyAlgorithm::Unknown(_) => Ok(PkeskBytes::Other), // we don't know the format of this data
            _ => unsupported_err!("unsupported algorithm for ESK"),
        }
    }
}

impl Serialize for PkeskBytes {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PkeskBytes::Rsa { mpi } => {
                mpi.to_writer(writer)?;
            }
            PkeskBytes::Elgamal { first, second } => {
                first.to_writer(writer)?;
                second.to_writer(writer)?;
            }
            PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            } => {
                public_point.to_writer(writer)?;

                // length of session key as one octet
                writer.write_u8(encrypted_session_key.len().try_into()?)?;

                writer.write_all(encrypted_session_key)?;
            }
            PkeskBytes::X25519 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X25519].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-
                if let Some(sym_alg) = sym_alg {
                    // len: algo octet + session_key len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    // len: esk len
                    writer.write_u8(session_key.len().try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }

                writer.write_all(session_key)?; // encrypted session key
            }
            PkeskBytes::X448 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X448].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
                if let Some(sym_alg) = sym_alg {
                    // len: algo + esk len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    // len: algo octet + session_key len
                    writer.write_u8(session_key.len().try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }

                writer.write_all(session_key)?; // encrypted session key
            }
            PkeskBytes::Other => {
                // Nothing to do
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            PkeskBytes::Rsa { mpi } => {
                sum += mpi.write_len();
            }
            PkeskBytes::Elgamal { first, second } => {
                sum += first.write_len();
                sum += second.write_len();
            }
            PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            } => {
                sum += public_point.write_len();
                // length of session key as one octets
                sum += 1;
                sum += encrypted_session_key.len();
            }
            PkeskBytes::X25519 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                sum += ephemeral.len();

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X25519].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-
                if sym_alg.is_some() {
                    // len: algo octet + session_key len
                    sum += 1 + 1;
                } else {
                    // len: esk len
                    sum += 1;
                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }
                sum += session_key.len(); // encrypted session key
            }
            PkeskBytes::X448 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                sum += ephemeral.len();

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X448].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
                if sym_alg.is_some() {
                    // len: algo + esk len
                    sum += 1 + 1;
                } else {
                    // len: algo octet + session_key len
                    sum += 1;
                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }
                sum += session_key.len(); // encrypted session key
            }
            PkeskBytes::Other => {}
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use prop::collection;

    use super::*;

    impl Arbitrary for PkeskBytes {
        type Parameters = (PublicKeyAlgorithm, bool);
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary() -> Self::Strategy {
            any::<(PublicKeyAlgorithm, bool)>()
                .prop_flat_map(Self::arbitrary_with)
                .boxed()
        }

        fn arbitrary_with((alg, is_v6): Self::Parameters) -> Self::Strategy {
            match alg {
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSAEncrypt
                | PublicKeyAlgorithm::RSASign => {
                    any::<Mpi>().prop_map(|mpi| Self::Rsa { mpi }).boxed()
                }
                PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalEncrypt => {
                    any::<(Mpi, Mpi)>()
                        .prop_map(|(first, second)| Self::Elgamal { first, second })
                        .boxed()
                }
                PublicKeyAlgorithm::ECDH => any::<Mpi>()
                    .prop_flat_map(|a| (Just(a), collection::vec(0u8..255u8, 1..100)))
                    .prop_map(|(a, b)| Self::Ecdh {
                        public_point: a,
                        encrypted_session_key: b.into(),
                    })
                    .boxed(),
                PublicKeyAlgorithm::X25519 => any::<([u8; 32], SymmetricKeyAlgorithm)>()
                    .prop_flat_map(|(a, b)| (Just(a), Just(b), collection::vec(0u8..255u8, 1..100)))
                    .prop_map(move |(a, b, c)| Self::X25519 {
                        ephemeral: a,
                        session_key: c.into(),
                        sym_alg: (!is_v6).then_some(b),
                    })
                    .boxed(),
                PublicKeyAlgorithm::X448 => any::<([u8; 56], SymmetricKeyAlgorithm)>()
                    .prop_flat_map(|(a, b)| (Just(a), Just(b), collection::vec(0u8..255u8, 1..100)))
                    .prop_map(move |(a, b, c)| Self::X448 {
                        ephemeral: a,
                        session_key: c.into(),
                        sym_alg: (!is_v6).then_some(b),
                    })
                    .boxed(),
                _ => unreachable!("unsupported {:?}", alg),
            }
        }
    }
}
