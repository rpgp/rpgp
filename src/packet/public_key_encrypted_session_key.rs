use std::io;

use byteorder::WriteBytesExt;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::number::streaming::be_u8;
use nom::sequence::pair;
use rand::{CryptoRng, Rng};

use crate::crypto::checksum;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::message::EskBytes;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::EskType;
use crate::types::{
    mpi, Fingerprint, KeyId, KeyVersion, PublicKeyTrait, PublicParams, Tag, Version,
};

/// Public Key Encrypted Session Key Packet
/// <https://tools.ietf.org/html/rfc4880.html#section-5.1>
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum PublicKeyEncryptedSessionKey {
    V3 {
        packet_version: Version,
        id: KeyId,
        pk_algo: PublicKeyAlgorithm,
        values: EskBytes,
    },

    V6 {
        packet_version: Version,
        key_version: Option<KeyVersion>,
        fingerprint: Option<Fingerprint>,
        pk_algo: PublicKeyAlgorithm,
        values: EskBytes,
    },

    Other {
        packet_version: Version,
        version: u8,
    },
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(version)(input)?;

        Ok(pk)
    }

    /// Encrypts the given session key as a v3 pkesk, to the passed in public key.
    pub fn from_session_key<R: CryptoRng + Rng>(
        rng: R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the session key is prefixed with symmetric key algorithm
        let len = session_key.len();
        let mut data = vec![0u8; len + 1];
        data[0] = u8::from(alg);
        data[1..=len].copy_from_slice(session_key);

        // Append a checksum, except for x25519/x448
        // FIXME: factor this difference out and up?
        match pkey.public_params() {
            PublicParams::X25519 { .. } | PublicParams::X448 { .. } => {}
            _ => {
                // and appended a checksum
                data.extend_from_slice(&checksum::calculate_simple(session_key).to_be_bytes())
            }
        }

        let values = pkey.encrypt(rng, &data, EskType::V3_4)?;

        Ok(PublicKeyEncryptedSessionKey::V3 {
            packet_version: Default::default(),
            id: pkey.key_id(),
            pk_algo: pkey.algorithm(),
            values,
        })
    }

    /// Encrypts the given session key to the passed in public key, as a v6 pkesk.
    /// FIXME: cleanup/DRY with from_session_key
    pub fn from_session_key6<R: CryptoRng + Rng>(
        rng: &mut R,
        session_key: &[u8],
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the session key
        let mut data = session_key.to_vec();

        // Append a checksum, except for x25519/x448
        // FIXME: factor this difference out and up?
        match pkey.public_params() {
            PublicParams::X25519 { .. } | PublicParams::X448 { .. } => {}
            _ => data.extend_from_slice(&checksum::calculate_simple(session_key).to_be_bytes()),
        }

        let values = pkey.encrypt(rng, &data, EskType::V6)?;

        Ok(PublicKeyEncryptedSessionKey::V6 {
            packet_version: Default::default(),
            key_version: Some(pkey.version()),
            fingerprint: Some(pkey.fingerprint()),
            pk_algo: pkey.algorithm(),
            values,
        })
    }

    /// Check if a Key matches with this PKESK's target
    /// - for v3: is PKESK key id the wildcard, or does it match `id`?
    /// - for v6: is PKESK fingerprint the wildcard (represented as `None`), or does it match `fp`?
    pub fn match_identity(&self, key_id: &KeyId, fp: &Fingerprint) -> bool {
        match self {
            Self::V3 { id, .. } => id.is_wildcard() || (id == key_id),
            Self::V6 { fingerprint, .. } => {
                if let Some(fingerprint) = fingerprint {
                    fingerprint == fp
                } else {
                    true // wildcard always matches
                }
            }
            _ => false,
        }
    }

    pub fn id(&self) -> &KeyId {
        match self {
            Self::V3 { id, .. } => id,
            _ => unimplemented!(), // FIXME
        }
    }

    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        match self {
            Self::V6 { fingerprint, .. } => fingerprint.as_ref(),
            _ => None,
        }
    }

    pub fn values(&self) -> &EskBytes {
        match self {
            Self::V3 { values, .. } | Self::V6 { values, .. } => values,
            _ => unimplemented!(),
        }
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Self::V3 { pk_algo, .. } | Self::V6 { pk_algo, .. } => *pk_algo,
            _ => unimplemented!(),
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V3 { .. } => 3,
            Self::V6 { .. } => 6,
            Self::Other { version, .. } => *version,
        }
    }
}

fn parse_esk<'i>(
    alg: &PublicKeyAlgorithm,
    i: &'i [u8],
    version: u8,
) -> IResult<&'i [u8], EskBytes> {
    match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign | PublicKeyAlgorithm::RSAEncrypt => {
            map(mpi, |v| EskBytes::Rsa { mpi: v.to_owned() })(i)
        }
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => {
            map(pair(mpi, mpi), |(first, second)| EskBytes::Elgamal {
                first: first.to_owned(),
                second: second.to_owned(),
            })(i)
        }
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::DiffieHellman => {
            Ok((i, EskBytes::Other))
        }
        PublicKeyAlgorithm::ECDH => {
            let (i, a) = mpi(i)?;
            let (i, blen) = be_u8(i)?;
            let (i, b) = take(blen)(i)?;

            Ok((
                i,
                EskBytes::Ecdh {
                    public_point: a.to_owned(),
                    encrypted_session_key: b.into(),
                },
            ))
        }
        PublicKeyAlgorithm::X25519 => {
            // 32 octets representing an ephemeral X25519 public key.
            let (i, ephemeral_public) = nom::bytes::complete::take(32u8)(i)?;

            // A one-octet size of the following fields.
            let (i, len) = be_u8(i)?;

            let (i, sym_alg) = if version != 6 {
                // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
                map(be_u8, SymmetricKeyAlgorithm::from)(i).map(|(i, alg)| (i, Some(alg)))?
            } else {
                (i, None)
            };

            let take = if version == 6 { len } else { len - 1 };

            // The encrypted session key.
            let (i, esk) = nom::bytes::complete::take(take)(i)?;

            Ok((
                i,
                EskBytes::X25519 {
                    ephemeral: ephemeral_public.try_into().expect("FIXME"),
                    sym_alg,
                    session_key: esk.to_vec(),
                },
            ))
        }
        PublicKeyAlgorithm::X448 => {
            // 56 octets representing an ephemeral X448 public key.
            let (i, ephemeral_public) = nom::bytes::complete::take(56u8)(i)?;

            // A one-octet size of the following fields.
            let (i, len) = be_u8(i)?;

            let (i, sym_alg) = if version != 6 {
                // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
                map(be_u8, SymmetricKeyAlgorithm::from)(i).map(|(i, alg)| (i, Some(alg)))?
            } else {
                (i, None)
            };

            let take = if version == 6 { len } else { len - 1 };

            // The encrypted session key.
            let (i, esk) = nom::bytes::complete::take(take)(i)?;

            Ok((
                i,
                EskBytes::X448 {
                    ephemeral: ephemeral_public.try_into().expect("56"),
                    sym_alg,
                    session_key: esk.to_vec(),
                },
            ))
        }
        PublicKeyAlgorithm::Unknown(_) => Ok((i, EskBytes::Other)), // we don't know the format of this data
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
}

/// Parses a Public-Key Encrypted Session Key Packets.
fn parse(
    packet_version: Version,
) -> impl Fn(&[u8]) -> IResult<&[u8], PublicKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        // version, 3 and 6 are allowed
        let (i, version) = be_u8(i)?;

        if version == 3 {
            // the key id this maps to
            let (i, id) = map_res(take(8u8), KeyId::from_slice)(i)?;
            // the public key algorithm
            let (i, pk_algo) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

            // key algorithm specific data
            let (i, values) = parse_esk(&pk_algo, i, version)?;

            Ok((
                i,
                PublicKeyEncryptedSessionKey::V3 {
                    packet_version,
                    id,
                    pk_algo,
                    values,
                },
            ))
        } else if version == 6 {
            // A one-octet size of the following two fields. This size may be zero,
            // if the key version number field and the fingerprint field are omitted
            // for an "anonymous recipient" (see Section 5.1.8).
            let (i, len) = be_u8(i)?;

            let (i, key_version, fingerprint) = match len {
                0 => (i, None, None),
                _ => {
                    // A one octet key version number.
                    let (i, v) = map(be_u8, KeyVersion::from)(i)?;

                    // The fingerprint of the public key or subkey to which the session key is encrypted. Note that the length N of the fingerprint for a version 4 key is 20 octets; for a version 6 key N is 32.
                    let (i, fp) = nom::bytes::complete::take(len - 1)(i)?;

                    let fp = Fingerprint::new(v, fp)?;

                    (i, Some(v), Some(fp))
                }
            };

            // A one-octet number giving the public-key algorithm used.
            let (i, pk_algo) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

            // A series of values comprising the encrypted session key. This is algorithm-specific and described below.
            let (i, values) = parse_esk(&pk_algo, i, version)?; // FIXME: shouldn't be Mpis

            Ok((
                i,
                PublicKeyEncryptedSessionKey::V6 {
                    packet_version,
                    key_version,
                    fingerprint,
                    pk_algo,
                    values,
                },
            ))
        } else {
            Ok((
                i,
                PublicKeyEncryptedSessionKey::Other {
                    packet_version,
                    version,
                },
            ))
        }
    }
}

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version())?;

        match self {
            PublicKeyEncryptedSessionKey::V3 { id, .. } => writer.write_all(id.as_ref())?,
            PublicKeyEncryptedSessionKey::V6 {
                key_version,
                fingerprint,
                ..
            } => {
                // A one-octet size of the following two fields. This size may be zero, if the key version number field and the fingerprint field are omitted for an "anonymous recipient" (see Section 5.1.8).
                match (key_version, fingerprint) {
                    (Some(key_version), Some(fingerprint)) => {
                        let len = fingerprint.len() + 1;
                        writer.write_u8(len.try_into()?)?;

                        // A one octet key version number.
                        writer.write_u8((*key_version).into())?;

                        // The fingerprint of the public key or subkey to which the session key is encrypted. Note that the length N of the fingerprint for a version 4 key is 20 octets; for a version 6 key N is 32.
                        writer.write_all(fingerprint.as_bytes())?;
                    }
                    _ => writer.write_u8(0)?,
                }
            }
            PublicKeyEncryptedSessionKey::Other { .. } => todo!(),
        }

        writer.write_u8(self.algorithm().into())?;

        match (self.algorithm(), self.values()) {
            (
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSASign
                | PublicKeyAlgorithm::RSAEncrypt,
                EskBytes::Rsa { mpi },
            ) => {
                mpi.to_writer(writer)?;
            }
            (
                PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign,
                EskBytes::Elgamal { first, second },
            ) => {
                first.to_writer(writer)?;
                second.to_writer(writer)?;
            }
            (
                PublicKeyAlgorithm::ECDH,
                EskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => {
                public_point.to_writer(writer)?;

                // The second value is not encoded as an actual MPI, but rather as a length prefixed
                // number.
                writer.write_u8(encrypted_session_key.len().try_into()?)?;

                writer.write_all(encrypted_session_key)?;
            }
            (
                PublicKeyAlgorithm::X25519,
                EskBytes::X25519 {
                    ephemeral,
                    sym_alg,
                    session_key,
                },
            ) => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted.
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-
                if let Some(sym_alg) = sym_alg {
                    // len: algo + esk len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                    writer.write_u8((*sym_alg).into())?;
                } else {
                    // len: esk len
                    writer.write_u8(session_key.len().try_into()?)?;
                }

                writer.write_all(session_key)?; // ESK
            }
            (
                PublicKeyAlgorithm::X448,
                EskBytes::X448 {
                    ephemeral,
                    sym_alg,
                    session_key,
                },
            ) => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted.
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
                if let Some(sym_alg) = sym_alg {
                    // len: algo + esk len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                    writer.write_u8((*sym_alg).into())?;
                } else {
                    // len: esk len
                    writer.write_u8(session_key.len().try_into()?)?;
                }

                writer.write_all(session_key)?; // ESK
            }
            (alg, _) => {
                bail!("failed to write EskBytes for {:?}", alg);
            }
        }

        Ok(())
    }
}

impl PacketTrait for PublicKeyEncryptedSessionKey {
    fn packet_version(&self) -> Version {
        match self {
            Self::V3 { packet_version, .. }
            | Self::V6 { packet_version, .. }
            | Self::Other { packet_version, .. } => *packet_version,
        }
    }
    fn tag(&self) -> Tag {
        Tag::PublicKeyEncryptedSessionKey
    }
}
