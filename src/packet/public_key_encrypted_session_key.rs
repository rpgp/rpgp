use std::io;

use byteorder::WriteBytesExt;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::number::streaming::be_u8;
use nom::sequence::pair;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::crypto::checksum;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{
    mpi, EskType, Fingerprint, KeyId, KeyVersion, PkeskBytes, PkeskVersion, PublicKeyTrait,
    PublicParams, Tag, Version,
};

/// Public Key Encrypted Session Key Packet (PKESK)
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-encrypted-sessio>
///
/// A PKESK contains an encrypted session key that has been encrypted to a specific public key.
/// PKESK are used in combination with a symmetric encryption container:
///
/// - V3 PKESK are used in combination with [version 1 Symmetrically Encrypted and Integrity
///   Protected Data Packets](https://www.rfc-editor.org/rfc/rfc9580.html#name-version-1-symmetrically-enc).
/// - V6 PKESK are used in combination with [version 2 Symmetrically Encrypted and Integrity
///   Protected Data Packets](https://www.rfc-editor.org/rfc/rfc9580.html#name-version-2-symmetrically-enc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyEncryptedSessionKey {
    V3 {
        packet_version: Version,
        id: KeyId,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
    },

    V6 {
        packet_version: Version,
        fingerprint: Option<Fingerprint>,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
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

    /// Prepare the session key data for encryption in a PKESK.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-encrypted-sessio>
    fn prepare_session_key_for_encryption(
        alg: Option<SymmetricKeyAlgorithm>, // set for pkesk v3
        sk: &[u8],
        pp: &PublicParams,
    ) -> Zeroizing<Vec<u8>> {
        let mut data = Zeroizing::new(Vec::with_capacity(1 + sk.len() + 2)); // max required capacity (for v3 and not-x22519/449)

        // Prefix session key with symmetric key algorithm (for v3 PKESK)
        if let Some(alg) = alg {
            data.push(u8::from(alg));
        }

        // Add the raw session key data
        data.extend_from_slice(sk);

        // Appended a checksum of the session key (except for X25519 and X448)
        match pp {
            PublicParams::X25519 { .. } => {}
            #[cfg(feature = "x448")]
            PublicParams::X448 { .. } => {}
            _ => data.extend_from_slice(&checksum::calculate_simple(sk).to_be_bytes()),
        }

        data
    }

    /// Encrypts the given session key to `pkey` as a v3 pkesk.
    pub fn from_session_key_v3<R: CryptoRng + Rng>(
        rng: R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the symmetric key algorithm, the session key, and a checksum (for some algorithms)
        let data =
            Self::prepare_session_key_for_encryption(Some(alg), session_key, pkey.public_params());

        let values = pkey.encrypt(rng, &data, EskType::V3_4)?;

        Ok(PublicKeyEncryptedSessionKey::V3 {
            packet_version: Default::default(),
            id: pkey.key_id(),
            pk_algo: pkey.algorithm(),
            values,
        })
    }

    /// Encrypts the given session key to `pkey` as a v6 pkesk.
    pub fn from_session_key_v6<R: CryptoRng + Rng>(
        rng: R,
        session_key: &[u8],
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // "An implementation MUST NOT generate ElGamal v6 PKESK packets."
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1.4-6)
        if pkey.algorithm() == PublicKeyAlgorithm::Elgamal {
            bail!("ElGamal is not a legal encryption mechanism for v6 PKESK");
        }

        // the session key, and a checksum (for some algorithms)
        let data =
            Self::prepare_session_key_for_encryption(None, session_key, pkey.public_params());

        let values = pkey.encrypt(rng, &data, EskType::V6)?;

        Ok(PublicKeyEncryptedSessionKey::V6 {
            packet_version: Default::default(),
            fingerprint: Some(pkey.fingerprint()),
            pk_algo: pkey.algorithm(),
            values,
        })
    }

    /// Check if a Key matches with this PKESK's target
    /// - for v3: is PKESK key id the wildcard, or does it match the key id of `pkey`?
    /// - for v6: is PKESK fingerprint the wildcard (represented as `None`), or does it match the fingerprint of `pkey`?
    pub fn match_identity(&self, pkey: &impl PublicKeyTrait) -> bool {
        match self {
            Self::V3 { id, .. } => id.is_wildcard() || (id == &pkey.key_id()),
            Self::V6 { fingerprint, .. } => {
                if let Some(fingerprint) = fingerprint {
                    fingerprint == &pkey.fingerprint()
                } else {
                    true // wildcard always matches
                }
            }
            _ => false,
        }
    }

    /// The Key ID in this PKESK. Only available for v3 PKESK (the function returns an Error for v6 PKESK).
    ///
    /// The Key ID may consist of all Zero-Bytes (if the PKESK was created for an anonymous recipient).
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1.1-3.2>
    pub fn id(&self) -> Result<&KeyId> {
        match self {
            Self::V3 { id, .. } => Ok(id),
            _ => bail!("KeyID is only available for V3 PKESK"),
        }
    }

    /// The Fingerprint in this PKESK. Only available for v6 PKESK (the function returns an Error for v3 PKESK).
    ///
    /// Additionally, the Fingerprint may be `None` (if the PKESK was created for an anonymous recipient).
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1.2-3.2>
    pub fn fingerprint(&self) -> Result<Option<&Fingerprint>> {
        match self {
            Self::V6 { fingerprint, .. } => Ok(fingerprint.as_ref()),
            _ => bail!("Fingerprint is only available for V6 PKESK"),
        }
    }

    /// The raw encrypted session key data inside this PKESK.
    /// This data is algorithm specific.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-f>
    /// and the following sections.
    pub fn values(&self) -> Result<&PkeskBytes> {
        match self {
            Self::V3 { values, .. } | Self::V6 { values, .. } => Ok(values),
            Self::Other { version, .. } => bail!("Unsupported PKESK version {}", version),
        }
    }

    /// The public key algorithm used in this PKESK.
    ///
    /// An error is returned for unsupported PKESK versions (any version except "3" and "6").
    pub fn algorithm(&self) -> Result<PublicKeyAlgorithm> {
        match self {
            Self::V3 { pk_algo, .. } | Self::V6 { pk_algo, .. } => Ok(*pk_algo),
            _ => bail!("PublicKeyAlgorithm unknown for {:?}", self),
        }
    }

    /// The version of this PKESK (currently "3" and "6" are expected values)
    pub fn version(&self) -> PkeskVersion {
        match self {
            Self::V3 { .. } => PkeskVersion::V3,
            Self::V6 { .. } => PkeskVersion::V6,
            Self::Other { version, .. } => PkeskVersion::Other(*version),
        }
    }
}

fn parse_esk<'i>(
    alg: &PublicKeyAlgorithm,
    i: &'i [u8],
    version: u8,
) -> IResult<&'i [u8], PkeskBytes> {
    match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign | PublicKeyAlgorithm::RSAEncrypt => {
            map(mpi, |v| PkeskBytes::Rsa { mpi: v.to_owned() })(i)
        }
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => {
            map(pair(mpi, mpi), |(first, second)| PkeskBytes::Elgamal {
                first: first.to_owned(),
                second: second.to_owned(),
            })(i)
        }
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::DiffieHellman => {
            Ok((i, PkeskBytes::Other))
        }
        PublicKeyAlgorithm::ECDH => {
            let (i, a) = mpi(i)?;
            let (i, blen) = be_u8(i)?;
            let (i, b) = take(blen)(i)?;

            Ok((
                i,
                PkeskBytes::Ecdh {
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

            // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
            let (i, sym_alg) = if version == 3 {
                map(be_u8, SymmetricKeyAlgorithm::from)(i).map(|(i, alg)| (i, Some(alg)))?
            } else {
                (i, None)
            };

            let skey_len = if version == 3 { len - 1 } else { len };

            // The encrypted session key.
            let (i, esk) = nom::bytes::complete::take(skey_len)(i)?;

            Ok((
                i,
                PkeskBytes::X25519 {
                    ephemeral: ephemeral_public.try_into().expect("32"),
                    sym_alg,
                    session_key: esk.to_vec(),
                },
            ))
        }
        #[cfg(feature = "x448")]
        PublicKeyAlgorithm::X448 => {
            // 56 octets representing an ephemeral X448 public key.
            let (i, ephemeral_public) = nom::bytes::complete::take(56u8)(i)?;

            // A one-octet size of the following fields.
            let (i, len) = be_u8(i)?;

            // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
            let (i, sym_alg) = if version == 3 {
                map(be_u8, SymmetricKeyAlgorithm::from)(i).map(|(i, alg)| (i, Some(alg)))?
            } else {
                (i, None)
            };

            let skey_len = if version == 3 { len - 1 } else { len };

            // The encrypted session key.
            let (i, esk) = nom::bytes::complete::take(skey_len)(i)?;

            Ok((
                i,
                PkeskBytes::X448 {
                    ephemeral: ephemeral_public.try_into().expect("56"),
                    sym_alg,
                    session_key: esk.to_vec(),
                },
            ))
        }
        PublicKeyAlgorithm::Unknown(_) => Ok((i, PkeskBytes::Other)), // we don't know the format of this data
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

            let (i, fingerprint) = match len {
                0 => (i, None),
                _ => {
                    // A one octet key version number.
                    let (i, v) = map(be_u8, KeyVersion::from)(i)?;

                    // The fingerprint of the public key or subkey to which the session key is encrypted.
                    // Note that the length N of the fingerprint for a version 4 key is 20 octets;
                    // for a version 6 key N is 32.
                    let (i, fp) = nom::bytes::complete::take(len - 1)(i)?;

                    let fp = Fingerprint::new(v, fp)?;

                    (i, Some(fp))
                }
            };

            // A one-octet number giving the public-key algorithm used.
            let (i, pk_algo) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

            // A series of values comprising the encrypted session key. This is algorithm-specific and described below.
            let (i, values) = parse_esk(&pk_algo, i, version)?;

            Ok((
                i,
                PublicKeyEncryptedSessionKey::V6 {
                    packet_version,
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
        writer.write_u8(self.version().into())?;

        match self {
            PublicKeyEncryptedSessionKey::V3 { id, .. } => writer.write_all(id.as_ref())?,
            PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => {
                // A one-octet size of the following two fields.
                // This size may be zero, if the key version number field and the fingerprint field
                // are omitted for an "anonymous recipient" (see Section 5.1.8).
                match fingerprint {
                    Some(fingerprint) => {
                        let len = fingerprint.len() + 1;
                        writer.write_u8(len.try_into()?)?;

                        // A one octet key version number.
                        match fingerprint.version() {
                            Some(version) => writer.write_u8(version.into())?,
                            None => {
                                bail!("Fingerprint without version information {:?}", fingerprint)
                            }
                        }

                        // The fingerprint of the public key or subkey to which the session key is encrypted.
                        // Note that the length N of the fingerprint for a version 4 key is 20 octets;
                        // for a version 6 key N is 32.
                        writer.write_all(fingerprint.as_bytes())?;
                    }
                    _ => writer.write_u8(0)?,
                }
            }
            PublicKeyEncryptedSessionKey::Other { .. } => todo!(),
        }

        let algorithm = self.algorithm()?;
        writer.write_u8(algorithm.into())?;

        match (algorithm, self.values()?) {
            (
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSASign
                | PublicKeyAlgorithm::RSAEncrypt,
                PkeskBytes::Rsa { mpi },
            ) => {
                mpi.to_writer(writer)?;
            }
            (
                PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign,
                PkeskBytes::Elgamal { first, second },
            ) => {
                first.to_writer(writer)?;
                second.to_writer(writer)?;
            }
            (
                PublicKeyAlgorithm::ECDH,
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => {
                public_point.to_writer(writer)?;

                // length of session key as one octet
                writer.write_u8(encrypted_session_key.len().try_into()?)?;

                writer.write_all(encrypted_session_key)?;
            }
            (
                PublicKeyAlgorithm::X25519,
                PkeskBytes::X25519 {
                    ephemeral,
                    sym_alg,
                    session_key,
                },
            ) => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X25519].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-
                if let Some(sym_alg) = sym_alg {
                    ensure!(
                        matches!(self, PublicKeyEncryptedSessionKey::V3 { .. }),
                        "Inconsistent: X25519 SymmetricKeyAlgorithm is set for {:?} PKESK",
                        self.version()
                    );

                    // len: algo octet + session_key len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    ensure!(
                        matches!(self, PublicKeyEncryptedSessionKey::V6 { .. }),
                        "Inconsistent: X25519 SymmetricKeyAlgorithm is unset for {:?} PKESK",
                        self.version()
                    );

                    // len: esk len
                    writer.write_u8(session_key.len().try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }

                writer.write_all(session_key)?; // encrypted session key
            }
            #[cfg(feature = "x448")]
            (
                PublicKeyAlgorithm::X448,
                PkeskBytes::X448 {
                    ephemeral,
                    sym_alg,
                    session_key,
                },
            ) => {
                writer.write_all(ephemeral)?;

                // Unlike the other public-key algorithms, in the case of a v3 PKESK packet,
                // the symmetric algorithm ID is not encrypted [for X448].
                //
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-for-x
                if let Some(sym_alg) = sym_alg {
                    ensure!(
                        matches!(self, PublicKeyEncryptedSessionKey::V3 { .. }),
                        "Inconsistent: X448 SymmetricKeyAlgorithm is set for {:?} PKESK",
                        self.version()
                    );

                    // len: algo + esk len
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    ensure!(
                        matches!(self, PublicKeyEncryptedSessionKey::V6 { .. }),
                        "Inconsistent: X448 SymmetricKeyAlgorithm is unset for {:?} PKESK",
                        self.version()
                    );

                    // len: algo octet + session_key len
                    writer.write_u8(session_key.len().try_into()?)?;

                    // For v6 PKESK, sym_alg is None, and the algorithm is not written here
                }

                writer.write_all(session_key)?; // encrypted session key
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
