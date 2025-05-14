use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use rand::CryptoRng;
use zeroize::Zeroizing;

use crate::{
    composed::RawSessionKey,
    crypto::{checksum, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, ensure_eq, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, PkeskBytes,
        PkeskVersion, PublicParams, Tag,
    },
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
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyEncryptedSessionKey {
    V3 {
        packet_header: PacketHeader,
        id: KeyId,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
    },

    V6 {
        packet_header: PacketHeader,
        fingerprint: Option<Fingerprint>,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
    },

    Other {
        packet_header: PacketHeader,
        #[debug("{:X}", version)]
        version: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        ensure_eq!(
            packet_header.tag(),
            Tag::PublicKeyEncryptedSessionKey,
            "invalid tag"
        );
        // version, 3 and 6 are allowed
        let version = i.read_u8()?;

        match version {
            3 => {
                // the key id this maps to
                let key_id_raw = i.read_array::<8>()?;
                let key_id = KeyId::from(key_id_raw);

                // the public key algorithm
                let pk_algo = i.read_u8().map(PublicKeyAlgorithm::from)?;

                // key algorithm specific data
                let values = PkeskBytes::try_from_reader(&pk_algo, version, &mut i)?;

                Ok(PublicKeyEncryptedSessionKey::V3 {
                    packet_header,
                    id: key_id,
                    pk_algo,
                    values,
                })
            }
            6 => {
                // A one-octet size of the following two fields. This size may be zero,
                // if the key version number field and the fingerprint field are omitted
                // for an "anonymous recipient" (see Section 5.1.8).
                let len = i.read_u8()?;

                let fingerprint = match len {
                    0 => None,
                    _ => {
                        // A one octet key version number.
                        let v = i.read_u8().map(KeyVersion::from)?;

                        // The fingerprint of the public key or subkey to which the session key is encrypted.
                        // Note that the length N of the fingerprint for a version 4 key is 20 octets;
                        // for a version 6 key N is 32.
                        let fp = i.take_bytes((len - 1).into())?;
                        let fp = Fingerprint::new(v, &fp)?;

                        Some(fp)
                    }
                };

                // A one-octet number giving the public-key algorithm used.
                let pk_algo = i.read_u8().map(PublicKeyAlgorithm::from)?;

                // A series of values comprising the encrypted session key. This is algorithm-specific.
                let values = PkeskBytes::try_from_reader(&pk_algo, version, &mut i)?;

                Ok(PublicKeyEncryptedSessionKey::V6 {
                    packet_header,
                    fingerprint,
                    pk_algo,
                    values,
                })
            }
            _ => {
                let data = i.rest()?.freeze();
                Ok(PublicKeyEncryptedSessionKey::Other {
                    packet_header,
                    version,
                    data,
                })
            }
        }
    }

    /// Prepare the session key data for encryption in a PKESK.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-encrypted-sessio>
    fn prepare_session_key_for_encryption(
        alg: Option<SymmetricKeyAlgorithm>, // set for pkesk v3
        sk: &RawSessionKey,
        pp: &PublicParams,
    ) -> Zeroizing<Vec<u8>> {
        let mut data = Zeroizing::new(Vec::with_capacity(1 + sk.len() + 2)); // max required capacity (for v3 and not-x22519/449)

        // Prefix session key with symmetric key algorithm (for v3 PKESK)
        if let Some(alg) = alg {
            data.push(u8::from(alg));
        }

        // Add the raw session key data
        data.extend_from_slice(sk.as_ref());

        // If needed, appended a checksum of the session key
        match pp {
            PublicParams::X25519(_) | PublicParams::X448(_) => {}
            #[cfg(feature = "draft-pqc")]
            PublicParams::MlKem768X25519(_) | PublicParams::MlKem1024X448(_) => {}
            _ => data.extend_from_slice(&checksum::calculate_simple(sk.as_ref()).to_be_bytes()),
        }

        data
    }

    /// Encrypts the given session key to `pkey` as a v3 pkesk.
    pub fn from_session_key_v3<R: CryptoRng + ?Sized, E: EncryptionKey>(
        rng: &mut R,
        session_key: &RawSessionKey,
        alg: SymmetricKeyAlgorithm,
        enc: &E,
    ) -> Result<Self> {
        // the symmetric key algorithm, the session key, and a checksum (for some algorithms)
        let data =
            Self::prepare_session_key_for_encryption(Some(alg), session_key, enc.public_params());

        let values = enc.encrypt(rng, &data, EskType::V3_4)?;

        let id = enc.legacy_key_id();
        let len = write_len_v3(&id, &values);
        let packet_header =
            PacketHeader::new_fixed(Tag::PublicKeyEncryptedSessionKey, len.try_into()?);

        Ok(PublicKeyEncryptedSessionKey::V3 {
            packet_header,
            id,
            pk_algo: enc.algorithm(),
            values,
        })
    }

    /// Encrypts the given session key to `pkey` as a v6 pkesk.
    pub fn from_session_key_v6<R: CryptoRng + ?Sized, E: EncryptionKey>(
        rng: &mut R,
        session_key: &RawSessionKey,
        enc: &E,
    ) -> Result<Self> {
        // "An implementation MUST NOT generate ElGamal v6 PKESK packets."
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1.4-6)
        if enc.algorithm() == PublicKeyAlgorithm::Elgamal {
            bail!("ElGamal is not a legal encryption mechanism for v6 PKESK");
        }

        // the session key, and a checksum (for some algorithms)
        let data = Self::prepare_session_key_for_encryption(None, session_key, enc.public_params());

        let values = enc.encrypt(rng, &data, EskType::V6)?;
        let fingerprint = Some(enc.fingerprint());

        let len = write_len_v6(&values, &fingerprint);
        let packet_header =
            PacketHeader::new_fixed(Tag::PublicKeyEncryptedSessionKey, len.try_into()?);

        Ok(PublicKeyEncryptedSessionKey::V6 {
            packet_header,
            fingerprint,
            pk_algo: enc.algorithm(),
            values,
        })
    }

    /// Check if a Key matches with this PKESK's target
    /// - for v3: is PKESK key id the wildcard, or does it match the key id of `pkey`?
    /// - for v6: is PKESK fingerprint the wildcard (represented as `None`), or does it match the fingerprint of `pkey`?
    pub fn match_identity(&self, pkey: &impl KeyDetails) -> bool {
        match self {
            Self::V3 { id, .. } => id.is_wildcard() || (id == &pkey.legacy_key_id()),
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
            Self::Other { .. } => bail!("PublicKeyAlgorithm unknown for {:?}", self),
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

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version().into())?;

        let algorithm = match self {
            PublicKeyEncryptedSessionKey::V3 { id, pk_algo, .. } => {
                writer.write_all(id.as_ref())?;
                *pk_algo
            }
            PublicKeyEncryptedSessionKey::V6 {
                fingerprint,
                pk_algo,
                ..
            } => {
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
                *pk_algo
            }
            PublicKeyEncryptedSessionKey::Other { version, data, .. } => {
                writer.write_u8(*version)?;
                writer.write_all(data)?;
                return Ok(());
            }
        };

        writer.write_u8(algorithm.into())?;
        self.values()?.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            PublicKeyEncryptedSessionKey::V3 { id, values, .. } => write_len_v3(id, values),
            PublicKeyEncryptedSessionKey::V6 {
                fingerprint,
                values,
                ..
            } => write_len_v6(values, fingerprint),
            PublicKeyEncryptedSessionKey::Other { data, .. } => write_len_other(data.len()),
        }
    }
}

impl PacketTrait for PublicKeyEncryptedSessionKey {
    fn packet_header(&self) -> &PacketHeader {
        match self {
            Self::V3 { packet_header, .. }
            | Self::V6 { packet_header, .. }
            | Self::Other { packet_header, .. } => packet_header,
        }
    }
}

fn write_len_other(data_len: usize) -> usize {
    1 + 1 + data_len
}

fn write_len_v3(id: &KeyId, values: &PkeskBytes) -> usize {
    let mut sum = 1;

    sum += id.as_ref().len();
    sum += 1;
    sum += values.write_len();
    sum
}

fn write_len_v6(values: &PkeskBytes, fingerprint: &Option<Fingerprint>) -> usize {
    let mut sum = 1;
    // A one-octet size of the following two fields.
    // This size may be zero, if the key version number field and the fingerprint field
    // are omitted for an "anonymous recipient" (see Section 5.1.8).
    match fingerprint {
        Some(fingerprint) => {
            sum += 1;
            // A one octet key version number.
            match fingerprint.version() {
                Some(_) => {
                    sum += 1;
                }
                None => {
                    panic!("Fingerprint without version information {fingerprint:?}")
                }
            }

            // The fingerprint of the public key or subkey to which the session key is encrypted.
            // Note that the length N of the fingerprint for a version 4 key is 20 octets;
            // for a version 6 key N is 32.
            sum += fingerprint.len();
        }
        _ => {
            sum += 1;
        }
    }
    sum += 1;
    sum += values.write_len();

    sum
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::types::{PacketHeaderVersion, PacketLength};

    impl Arbitrary for PublicKeyEncryptedSessionKey {
        type Parameters = PublicKeyAlgorithm;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary() -> Self::Strategy {
            any::<PublicKeyAlgorithm>()
                .prop_flat_map(Self::arbitrary_with)
                .boxed()
        }
        fn arbitrary_with(alg: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                any_with::<PkeskBytes>((alg, false))
                    .prop_flat_map(|values| {
                        (any::<PacketHeaderVersion>(), any::<KeyId>(), Just(values))
                    })
                    .prop_map(move |(packet_version, id, values)| {
                        let len = write_len_v3(&id, &values);
                        let len = PacketLength::Fixed(len.try_into().unwrap());
                        let packet_header = PacketHeader::from_parts(
                            packet_version,
                            Tag::PublicKeyEncryptedSessionKey,
                            len,
                        )
                        .unwrap();

                        Self::V3 {
                            packet_header,
                            id,
                            pk_algo: alg,
                            values,
                        }
                    }),
                any_with::<PkeskBytes>((alg, true))
                    .prop_flat_map(|values| {
                        (
                            any::<PacketHeaderVersion>(),
                            any::<Option<Fingerprint>>(),
                            Just(values),
                        )
                    })
                    .prop_map(move |(packet_version, fingerprint, values)| {
                        let len = write_len_v6(&values, &fingerprint);
                        let len = PacketLength::Fixed(len.try_into().unwrap());
                        let packet_header = PacketHeader::from_parts(
                            packet_version,
                            Tag::PublicKeyEncryptedSessionKey,
                            len,
                        )
                        .unwrap();

                        Self::V6 {
                            packet_header,
                            fingerprint,
                            pk_algo: alg,
                            values,
                        }
                    }),
            ]
            .boxed()
        }
    }

    fn gen_alg() -> impl Strategy<Value = PublicKeyAlgorithm> {
        use PublicKeyAlgorithm::*;
        prop_oneof![
            Just(RSA),
            Just(RSAEncrypt),
            Just(RSASign),
            Just(Elgamal),
            Just(ElgamalEncrypt),
            Just(ECDH),
            Just(X25519),
        ]
    }

    proptest! {
        #[test]
        fn write_len(
            (_alg, packet) in gen_alg().prop_flat_map(|alg| (Just(alg), any_with::<PublicKeyEncryptedSessionKey>(alg)))
        ) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), packet.write_len());
        }

        #[test]
        fn packet_roundtrip(
            (_alg, packet) in gen_alg().prop_flat_map(|alg| (Just(alg), any_with::<PublicKeyEncryptedSessionKey>(alg)))
        ) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = PublicKeyEncryptedSessionKey::try_from_reader(*packet.packet_header(), &mut &buf[..]).unwrap();
            prop_assert_eq!(packet, new_packet);
        }
    }
}
