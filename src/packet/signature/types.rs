use std::io::{BufRead, Read};

use bitfields::bitfield;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use digest::DynDigest;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
    crypto::{
        aead::AeadAlgorithm,
        hash::{HashAlgorithm, WriteHasher},
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, unimplemented_err, unsupported_err, Result},
    line_writer::LineBreak,
    normalize_lines::NormalizedReader,
    packet::{
        signature::SignatureConfig, PacketHeader, PacketTrait, SignatureVersionSpecific, Subpacket,
        SubpacketData,
    },
    parsing::BufParsing,
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        self, CompressionAlgorithm, Fingerprint, KeyDetails, KeyId, KeyVersion, PublicKeyTrait,
        SignatureBytes, Tag,
    },
};

/// Signature Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-packet-type-id-2>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Signature {
    packet_header: PacketHeader,
    pub inner: InnerSignature,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum InnerSignature {
    /// V2, V3, V4 and V6
    Known {
        config: SignatureConfig,
        #[debug("{}", hex::encode(signed_hash_value))]
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    },
    Unknown {
        version: SignatureVersion,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl Signature {
    /// Constructor for an OpenPGP v2 signature packet.
    /// Note: This is a historical packet version!
    #[allow(clippy::too_many_arguments)]
    pub fn v2(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets: vec![],
                    unhashed_subpackets: vec![],
                    version_specific: SignatureVersionSpecific::V2 { created, issuer },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    /// Constructor for an OpenPGP v3 signature packet.
    /// Note: This is a historical packet version!
    #[allow(clippy::too_many_arguments)]
    pub fn v3(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets: vec![],
                    unhashed_subpackets: vec![],
                    version_specific: SignatureVersionSpecific::V3 { created, issuer },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    /// Constructor for an OpenPGP v4 signature packet.
    ///
    /// OpenPGP v4 signatures are typically used with OpenPGP v4 keys, as specified in RFC 9580
    /// (and formerly in 4880 and 2440).
    #[allow(clippy::too_many_arguments)]
    pub fn v4(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets,
                    unhashed_subpackets,
                    version_specific: SignatureVersionSpecific::V4,
                },
                signed_hash_value,
                signature,
            },
        }
    }

    /// Constructor for an OpenPGP v6 signature packet.
    ///
    /// OpenPGP v6 signatures are specified in RFC 9580 and only used with OpenPGP v6 keys.
    #[allow(clippy::too_many_arguments)]
    pub fn v6(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
        salt: Vec<u8>,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets,
                    unhashed_subpackets,
                    version_specific: SignatureVersionSpecific::V6 { salt },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    /// Create a signature of unknown version
    pub fn unknown(packet_header: PacketHeader, version: SignatureVersion, data: Bytes) -> Self {
        Self {
            packet_header,
            inner: InnerSignature::Unknown { version, data },
        }
    }

    pub fn from_config(
        config: SignatureConfig,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Result<Self> {
        let len = match config.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let mut sum = 1;
                sum += config.write_len_v3();
                sum += 2; // signed hash value
                sum += signature.write_len();
                sum
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut sum = 1;
                sum += config.write_len_v4_v6();
                sum += 2; // signed hash value
                if let SignatureVersionSpecific::V6 { ref salt } = config.version_specific {
                    sum += 1;
                    sum += salt.len();
                }
                sum += signature.write_len();
                sum
            }
            SignatureVersion::V5 => {
                unsupported_err!("crate V5 signature")
            }
            SignatureVersion::Other(version) => unsupported_err!("signature version {}", version),
        };
        let packet_header = PacketHeader::new_fixed(Tag::Signature, len.try_into()?);

        Ok(Signature {
            packet_header,
            inner: InnerSignature::Known {
                config,
                signed_hash_value,
                signature,
            },
        })
    }

    pub fn config(&self) -> Option<&SignatureConfig> {
        match self.inner {
            InnerSignature::Known { ref config, .. } => Some(config),
            InnerSignature::Unknown { .. } => None,
        }
    }

    pub fn version(&self) -> SignatureVersion {
        match self.inner {
            InnerSignature::Known { ref config, .. } => config.version(),
            InnerSignature::Unknown { version, .. } => version,
        }
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> Option<SignatureType> {
        self.config().map(|c| c.typ())
    }

    /// The used `HashAlgorithm`.
    pub fn hash_alg(&self) -> Option<HashAlgorithm> {
        self.config().map(|c| c.hash_alg)
    }

    pub fn signature(&self) -> Option<&SignatureBytes> {
        match self.inner {
            InnerSignature::Known { ref signature, .. } => Some(signature),
            InnerSignature::Unknown { .. } => None,
        }
    }

    pub fn signed_hash_value(&self) -> Option<[u8; 2]> {
        match self.inner {
            InnerSignature::Known {
                signed_hash_value, ..
            } => Some(signed_hash_value),
            InnerSignature::Unknown { .. } => None,
        }
    }

    /// Does `key` match any issuer or issuer_fingerprint subpacket in `sig`?
    /// If yes, we consider `key` a candidate to verify `sig` against.
    ///
    /// We also consider `key` a match for `sig` by default, if `sig` contains no issuer-related
    /// subpackets.
    fn match_identity(sig: &Signature, key: &impl PublicKeyTrait) -> bool {
        let issuers = sig.issuer();
        let issuer_fps = sig.issuer_fingerprint();

        // If there is no subpacket that signals the issuer, we consider `sig` and `key` a
        // potential match, and will check the cryptographic validity.
        if issuers.is_empty() && issuer_fps.is_empty() {
            return true;
        }

        // Does any issuer or issuer fingerprint subpacket matche the identity of `sig`?
        issuers.iter().any(|&key_id| key_id == &key.key_id())
            || issuer_fps.iter().any(|&fp| fp == &key.fingerprint())
    }

    /// Check alignment between signing key version and signature version.
    ///
    /// Version 6 signatures and version 6 keys are strongly linked:
    /// - only a v6 key may produce a v6 signature
    /// - a v6 key may only produce v6 signatures
    fn check_signature_key_version_alignment(
        key: &impl PublicKeyTrait,
        config: &SignatureConfig,
    ) -> Result<()> {
        // Every signature made by a version 6 key MUST be a version 6 signature.
        if key.version() == KeyVersion::V6 {
            ensure_eq!(
                config.version(),
                SignatureVersion::V6,
                "Non v6 signature by a v6 key is not allowed"
            );
        }

        if config.version() == SignatureVersion::V6 {
            ensure_eq!(
                key.version(),
                KeyVersion::V6,
                "v6 signature by a non-v6 key is not allowed"
            );
        }

        Ok(())
    }

    /// Check if the hash algorithm is acceptable for the signature configuration
    /// (in particular, if it's allowed in combination with the public key algorithm).
    pub(crate) fn check_signature_hash_strength(config: &SignatureConfig) -> Result<()> {
        if config.pub_alg.is_pqc() {
            // For all signature algorithms in draft-ietf-openpgp-pqc-10,
            // hash digest sizes of at least 256 bits are required:
            //
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-signature-packet-tag-2
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#name-signature-packet-tag-2-2

            let Some(digest_size) = config.hash_alg.digest_size() else {
                bail!("Illegal hash_alg setting {}", config.hash_alg);
            };

            ensure!(
                digest_size * 8 >= 256,
                "PQC signatures must use hash algorithms with digest size >= 256 bits, {} is insufficient",
                config.hash_alg
            );
        }

        Ok(())
    }

    /// Verify this signature.
    pub fn verify<R>(&self, key: &impl PublicKeyTrait, data: R) -> Result<()>
    where
        R: Read,
    {
        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        Self::check_signature_key_version_alignment(&key, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, key),
            "verify: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            &key.key_id(),
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            // Salt size must match the expected length for the hash algorithm that is used
            //
            // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
            ensure_eq!(
                config.hash_alg.salt_len(),
                Some(salt.len()),
                "Illegal salt length {} for a V6 Signature using {:?}",
                salt.len(),
                config.hash_alg
            );

            hasher.update(salt.as_ref())
        }

        if matches!(self.typ(), Some(SignatureType::Text)) {
            let normalized = NormalizedReader::new(data, LineBreak::Crlf);

            config.hash_data_to_sign(&mut hasher, normalized)?;
        } else {
            config.hash_data_to_sign(&mut hasher, data)?;
        }
        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];

        // Check that the high 16 bits of the hash from the signature packet match with the hash we
        // just calculated.
        //
        // "When verifying a version 6 signature, an implementation MUST reject the signature if
        // these octets do not match the first two octets of the computed hash."
        //
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#name-notes-on-signatures)
        //
        // (Note: we currently also reject v4 signatures if the calculated hash doesn't match the
        // high 16 bits in the signature packet, even though RFC 9580 doesn't strictly require this)
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "signature: invalid signed hash value"
        );

        key.verify_signature(config.hash_alg, hash, signature)
    }

    /// Verifies a certification signature type (for self-signatures).
    pub fn verify_certification<P>(&self, key: &P, tag: Tag, id: &impl Serialize) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        self.verify_third_party_certification(&key, &key, tag, id)
    }

    /// Verifies a certification signature type (for third-party signatures).
    pub fn verify_third_party_certification<P, K>(
        &self,
        signee: &P,
        signer: &K,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
        K: PublicKeyTrait + Serialize,
    {
        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };
        let key_id = signee.key_id();
        debug!("verifying certification {:?} {:#?}", key_id, self);

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, signer),
            "verify_certification: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            key_id,
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        // the key of the signee
        {
            // TODO: this is different for V5
            serialize_for_hashing(signee, &mut hasher)?;
        }

        // the packet content
        {
            let packet_len = id.write_len();

            match config.version() {
                SignatureVersion::V2 | SignatureVersion::V3 => {
                    // Nothing to do
                }
                SignatureVersion::V4 | SignatureVersion::V6 => {
                    let prefix = match tag {
                        Tag::UserId => 0xB4,
                        Tag::UserAttribute => 0xD1,
                        _ => bail!("invalid tag for certification validation: {:?}", tag),
                    };

                    let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                    BigEndian::write_u32(&mut prefix_buf[1..], packet_len.try_into()?);

                    // prefixes
                    hasher.update(&prefix_buf);
                }
                SignatureVersion::V5 => {
                    bail!("v5 signature unsupported tpc")
                }
                SignatureVersion::Other(version) => {
                    bail!("unsupported signature version: {:?}", version)
                }
            }

            id.to_writer(&mut WriteHasher(&mut hasher))?;
        }

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "certification: invalid signed hash value"
        );

        signer.verify_signature(config.hash_alg, hash, signature)
    }

    /// Verifies a subkey binding (which binds a subkey to the primary key).
    ///
    /// The primary key is expected as `signer`, the subkey as `signee`.
    ///
    /// "Subkey Binding Signature (type ID 0x18)"
    pub fn verify_subkey_binding<P, K>(&self, signer: &P, signee: &K) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
        K: PublicKeyTrait + Serialize,
    {
        debug!(
            "verifying subkey binding: {:#?} - {:#?} - {:#?}",
            self, signer, signee,
        );

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signer, &mut hasher)?; // primary
        serialize_for_hashing(signee, &mut hasher)?; // subkey

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "subkey binding: invalid signed hash value"
        );

        signer.verify_signature(config.hash_alg, hash, signature)
    }

    /// Verifies a primary key binding signature, or "back signature" (which links the primary to a signing subkey).
    ///
    /// The subkey is expected as `signer`, the primary key as `signee`.
    ///
    /// "Primary Key Binding Signature (type ID 0x19)"
    pub fn verify_primary_key_binding<P, K>(&self, signer: &P, signee: &K) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
        K: PublicKeyTrait + Serialize,
    {
        debug!(
            "verifying primary key binding: {:#?} - {:#?} - {:#?}",
            self, signer, signee
        );

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?; // primary
        serialize_for_hashing(signer, &mut hasher)?; // subkey

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "key binding: invalid signed hash value"
        );

        signer.verify_signature(config.hash_alg, hash, signature)
    }

    /// Verifies a direct key signature or a revocation.
    pub fn verify_key<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        debug!("verifying key (revocation): {:#?} - {:#?}", self, key);

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };
        Self::check_signature_key_version_alignment(&key, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, key),
            "verify_key: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            &key.key_id(),
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(key, &mut hasher)?;

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "key: invalid signed hash value"
        );

        key.verify_signature(config.hash_alg, hash, signature)
    }

    /// Returns if the signature is a certification or not.
    pub fn is_certification(&self) -> bool {
        self.config()
            .map(|c| c.is_certification())
            .unwrap_or_default()
    }

    pub fn key_expiration_time(&self) -> Option<&Duration> {
        self.config().and_then(|h| {
            h.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::KeyExpirationTime(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn signature_expiration_time(&self) -> Option<&Duration> {
        self.config().and_then(|h| {
            h.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::SignatureExpirationTime(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn created(&self) -> Option<&DateTime<Utc>> {
        self.config().and_then(|c| c.created())
    }

    pub fn issuer(&self) -> Vec<&KeyId> {
        self.config().map(|c| c.issuer()).unwrap_or_default()
    }

    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.config()
            .map(|c| c.issuer_fingerprint())
            .unwrap_or_default()
    }

    pub fn preferred_symmetric_algs(&self) -> &[SymmetricKeyAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredSymmetricAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_aead_algs(&self) -> &[(SymmetricKeyAlgorithm, AeadAlgorithm)] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredAeadAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_hash_algs(&self) -> &[HashAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredHashAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_compression_algs(&self) -> &[CompressionAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredCompressionAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_server_prefs(&self) -> &[u8] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::KeyServerPreferences(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_flags(&self) -> KeyFlags {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::KeyFlags(flags) => Some(flags.clone()),
                    _ => None,
                })
            })
            .unwrap_or_default()
    }

    pub fn features(&self) -> Option<&Features> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::Features(feat) => Some(feat),
                _ => None,
            })
        })
    }

    pub fn revocation_reason_code(&self) -> Option<&RevocationCode> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationReason(code, _) => Some(code),
                _ => None,
            })
        })
    }

    pub fn revocation_reason_string(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationReason(_, reason) => Some(reason),
                _ => None,
            })
        })
    }

    pub fn is_primary(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::IsPrimary(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(false)
    }

    pub fn is_revocable(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::Revocable(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(true)
    }

    pub fn embedded_signature(&self) -> Option<&Signature> {
        // We consider data from both the hashed and unhashed area here, because the embedded
        // signature is inherently cryptographically secured. An attacker can't add a valid
        // embedded signature, canonicalization will remove any invalid embedded signature
        // subpackets.
        if let Some(sub) = self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::EmbeddedSignature(d) => Some(&**d),
                _ => None,
            })
        }) {
            return Some(sub);
        }
        if let Some(sub) = self.config().and_then(|c| {
            c.unhashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::EmbeddedSignature(d) => Some(&**d),
                _ => None,
            })
        }) {
            return Some(sub);
        }

        None
    }

    pub fn preferred_key_server(&self) -> Option<&str> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::PreferredKeyServer(d) => Some(d.as_str()),
                _ => None,
            })
        })
    }

    pub fn notations(&self) -> Vec<&Notation> {
        self.config()
            .map(|c| {
                c.hashed_subpackets()
                    .filter_map(|p| match &p.data {
                        SubpacketData::Notation(d) => Some(d),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn revocation_key(&self) -> Option<&types::RevocationKey> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationKey(d) => Some(d),
                _ => None,
            })
        })
    }

    /// Gets the user id of the signer
    ///
    /// Note that the user id may not be valid utf-8, if it was created
    /// using a different encoding. But since the RFC describes every
    /// text as utf-8 it is up to the caller whether to error on non utf-8 data.
    pub fn signers_userid(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::SignersUserID(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn policy_uri(&self) -> Option<&str> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::PolicyURI(d) => Some(d.as_ref()),
                _ => None,
            })
        })
    }

    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::TrustSignature(depth, value) => Some((*depth, *value)),
                _ => None,
            })
        })
    }

    pub fn regular_expression(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RegularExpression(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn exportable_certification(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::ExportableCertification(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(true)
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(#[debug("0x{:x}", _0)] u8),
}

impl Default for SignatureVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
pub enum SignatureType {
    /// Signature of a binary document.
    /// This means the signer owns it, created it, or certifies that it has not been modified.
    Binary = 0x00,
    /// Signature of a canonical text document.
    /// This means the signer owns it, created it, or certifies that it
    /// has not been modified.  The signature is calculated over the text
    /// data with its line endings converted to `<CR><LF>`.
    Text = 0x01,
    /// Standalone signature.
    /// This signature is a signature of only its own subpacket contents.
    /// It is calculated identically to a signature over a zero-length
    /// binary document.  Note that it doesn't make sense to have a V3 standalone signature.
    Standalone = 0x02,
    /// Generic certification of a User ID and Public-Key packet.
    /// The issuer of this certification does not make any particular
    /// assertion as to how well the certifier has checked that the owner
    /// of the key is in fact the person described by the User ID.
    CertGeneric = 0x10,
    /// Persona certification of a User ID and Public-Key packet.
    /// The issuer of this certification has not done any verification of
    /// the claim that the owner of this key is the User ID specified.
    CertPersona = 0x11,
    /// Casual certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done some casual
    /// verification of the claim of identity.
    CertCasual = 0x12,
    /// Positive certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done substantial
    /// verification of the claim of identity.
    ///
    /// Most OpenPGP implementations make their "key signatures" as 0x10
    /// certifications.  Some implementations can issue 0x11-0x13
    /// certifications, but few differentiate between the types.
    CertPositive = 0x13,
    /// Subkey Binding Signature
    /// This signature is a statement by the top-level signing key that
    /// indicates that it owns the subkey.  This signature is calculated
    /// directly on the primary key and subkey, and not on any User ID or
    /// other packets.  A signature that binds a signing subkey MUST have
    /// an Embedded Signature subpacket in this binding signature that
    /// contains a 0x19 signature made by the signing subkey on the
    /// primary key and subkey.
    SubkeyBinding = 0x18,
    /// Primary Key Binding Signature
    /// This signature is a statement by a signing subkey, indicating
    /// that it is owned by the primary key and subkey.  This signature
    /// is calculated the same way as a 0x18 signature: directly on the
    /// primary key and subkey, and not on any User ID or other packets.
    KeyBinding = 0x19,
    /// Signature directly on a key
    /// This signature is calculated directly on a key.  It binds the
    /// information in the Signature subpackets to the key, and is
    /// appropriate to be used for subpackets that provide information
    /// about the key, such as the Revocation Key subpacket.  It is also
    /// appropriate for statements that non-self certifiers want to make
    /// about the key itself, rather than the binding between a key and a name.
    Key = 0x1F,
    /// Key revocation signature
    /// The signature is calculated directly on the key being revoked.  A
    /// revoked key is not to be used.  Only revocation signatures by the
    /// key being revoked, or by an authorized revocation key, should be
    /// considered valid revocation signatures.
    KeyRevocation = 0x20,
    /// Subkey revocation signature
    /// The signature is calculated directly on the subkey being revoked.
    /// A revoked subkey is not to be used.  Only revocation signatures
    /// by the top-level signature key that is bound to this subkey, or
    /// by an authorized revocation key, should be considered valid
    /// revocation signatures.
    SubkeyRevocation = 0x28,
    /// Certification revocation signature
    /// This signature revokes an earlier User ID certification signature
    /// (signature class 0x10 through 0x13) or direct-key signature
    /// (0x1F).  It should be issued by the same key that issued the
    /// revoked signature or an authorized revocation key.  The signature
    /// is computed over the same data as the certificate that it
    /// revokes, and should have a later creation date than that
    /// certificate.
    CertRevocation = 0x30,
    /// Timestamp signature.
    /// This signature is only meaningful for the timestamp contained in
    /// it.
    Timestamp = 0x40,
    /// Third-Party Confirmation signature.
    /// This signature is a signature over some other OpenPGP Signature
    /// packet(s).  It is analogous to a notary seal on the signed data.
    /// A third-party signature SHOULD include Signature Target
    /// subpacket(s) to give easy identification.  Note that we really do
    /// mean SHOULD.  There are plausible uses for this (such as a blind
    /// party that only sees the signature, not the key or source
    /// document) that cannot include a target subpacket.
    ThirdParty = 0x50,

    #[num_enum(catch_all)]
    Other(#[cfg_attr(test, proptest(strategy = "0x51u8.."))] u8),
}

/// Key flags by default are only 1 byte large, but there are reserved
/// extensions making them 2 bytes large.
/// In addition the spec defines them to be arbitrarily large, but this is
/// not yet used.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags>
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyFlags {
    /// Handles the first two bytes.
    known: KnownKeyFlags,
    /// Any additional key flag bytes.
    rest: Option<Bytes>,
    /// Need to store this, to fully roundtrip..
    original_len: usize,
}

impl Default for KeyFlags {
    fn default() -> Self {
        Self {
            known: KnownKeyFlags::default(),
            rest: None,
            original_len: 1,
        }
    }
}

impl KeyFlags {
    /// Parse the key flags from the given buffer.
    pub fn try_from_reader<B: BufRead>(mut reader: B) -> Result<Self> {
        let mut buf = reader.rest()?.freeze();
        let remaining = buf.len();

        if remaining == 0 {
            return Ok(Self {
                known: KnownKeyFlags::default(),
                rest: None,
                original_len: remaining,
            });
        }
        if remaining == 1 {
            let known = KnownKeyFlags::from_bits(buf.read_u8()? as u16);
            return Ok(Self {
                known,
                rest: None,
                original_len: remaining,
            });
        }
        if remaining == 2 {
            let known = KnownKeyFlags::from_bits(buf.read_le_u16()?);
            return Ok(Self {
                known,
                rest: None,
                original_len: remaining,
            });
        }
        let known = KnownKeyFlags::from_bits(buf.read_le_u16()?);
        let rest = Some(buf.rest());
        Ok(Self {
            known,
            rest,
            original_len: remaining,
        })
    }

    pub fn set_certify(&mut self, val: bool) {
        self.known.set_certify(val);
    }
    pub fn set_encrypt_comms(&mut self, val: bool) {
        self.known.set_encrypt_comms(val);
    }
    pub fn set_encrypt_storage(&mut self, val: bool) {
        self.known.set_encrypt_storage(val);
    }
    pub fn set_sign(&mut self, val: bool) {
        self.known.set_sign(val);
    }
    pub fn set_shared(&mut self, val: bool) {
        self.known.set_shared(val);
    }
    pub fn set_authentication(&mut self, val: bool) {
        self.known.set_authentication(val);
    }
    pub fn set_group(&mut self, val: bool) {
        self.known.set_group(val);
    }

    pub fn set_adsk(&mut self, val: bool) {
        self.known.set_adsk(val);
    }

    pub fn set_timestamping(&mut self, val: bool) {
        self.known.set_timestamping(val);
    }

    pub fn certify(&self) -> bool {
        self.known.certify()
    }

    pub fn encrypt_comms(&self) -> bool {
        self.known.encrypt_comms()
    }

    pub fn encrypt_storage(&self) -> bool {
        self.known.encrypt_storage()
    }

    pub fn sign(&self) -> bool {
        self.known.sign()
    }

    pub fn shared(&self) -> bool {
        self.known.shared()
    }

    pub fn authentication(&self) -> bool {
        self.known.authentication()
    }

    pub fn group(&self) -> bool {
        self.known.group()
    }

    pub fn adsk(&self) -> bool {
        self.known.adsk()
    }

    pub fn timestamping(&self) -> bool {
        self.known.timestamping()
    }
}

impl Serialize for KeyFlags {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        if self.original_len == 0 {
            return Ok(());
        }

        let [a, b] = self.known.into_bits().to_le_bytes();
        writer.write_u8(a)?;

        if self.original_len > 1 || b != 0 {
            writer.write_u8(b)?;
        }

        if let Some(ref rest) = self.rest {
            writer.write_all(rest)?;
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        if self.original_len == 0 {
            return 0;
        }
        let mut sum = 0;
        let [_, b] = self.known.into_bits().to_le_bytes();
        if self.original_len > 1 || b > 0 {
            sum += 2;
        } else {
            sum += 1;
        }

        if let Some(ref rest) = self.rest {
            sum += rest.len();
        }
        sum
    }
}

#[bitfield(u16, order = lsb)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct KnownKeyFlags {
    #[bits(1)]
    certify: bool,
    #[bits(1)]
    sign: bool,
    #[bits(1)]
    encrypt_comms: bool,
    #[bits(1)]
    encrypt_storage: bool,
    #[bits(1)]
    shared: bool,
    #[bits(1)]
    authentication: bool,
    #[bits(1)]
    _padding0: u8,
    #[bits(1)]
    group: bool,
    #[bits(2)]
    _padding1: u8,
    #[bits(1)]
    adsk: bool,
    #[bits(1)]
    timestamping: bool,
    #[bits(4)]
    _padding2: u8,
}

/// Signals capabilities of the keyholder's OpenPGP software.
///
/// Features are encoded as "N octets of flags", but currently typically use 1 byte.
/// (Only the first 4 bits have been used so far)
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-features>
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Features {
    /// Handles the first byte.
    /// Can be None to encode Features subpackets that are 0 byte long.
    first: Option<KnownFeatures>,

    /// Any additional features bytes.
    /// (Must be empty if "known" is None.)
    rest: Vec<u8>,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            first: Some(KnownFeatures::default()),
            rest: vec![],
        }
    }
}

impl From<&[u8]> for Features {
    fn from(value: &[u8]) -> Self {
        match value.len() {
            0 => Self {
                first: None,
                rest: vec![],
            },
            _ => Self {
                first: Some(KnownFeatures(value[0])),
                rest: value[1..].to_vec(),
            },
        }
    }
}

impl From<&Features> for Vec<u8> {
    fn from(value: &Features) -> Self {
        let mut v = vec![];
        value.to_writer(&mut v).expect("vec");
        v
    }
}

impl From<KnownFeatures> for Features {
    fn from(value: KnownFeatures) -> Self {
        Self {
            first: Some(value),
            rest: vec![],
        }
    }
}

impl Features {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seipd_v1(&self) -> bool {
        match self.first {
            Some(k) => k.seipd_v1(),
            None => false,
        }
    }

    pub fn set_seipd_v1(&mut self, val: bool) {
        if self.first.is_none() {
            self.first = Some(KnownFeatures::default());
        }

        // Should always be Some!
        if let Some(k) = self.first.as_mut() {
            k.set_seipd_v1(val);
        }
    }

    pub fn seipd_v2(&self) -> bool {
        match self.first {
            Some(k) => k.seipd_v2(),
            None => false,
        }
    }

    pub fn set_seipd_v2(&mut self, val: bool) {
        if self.first.is_none() {
            self.first = Some(KnownFeatures::default());
        }

        // Should always be Some!
        if let Some(k) = self.first.as_mut() {
            k.set_seipd_v2(val);
        }
    }
}

impl Serialize for Features {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        if let Some(k) = self.first {
            writer.write_u8(k.0)?;
            writer.write_all(&self.rest)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        if self.first.is_none() {
            0
        } else {
            1 + self.rest.len()
        }
    }
}

/// Encodes the first byte of a Features.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-features>
#[bitfield(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct KnownFeatures {
    /// Support for "Version 1 Symmetrically Encrypted and Integrity Protected Data packet"
    #[bits(1)]
    seipd_v1: bool,

    /// Not standardized in OpenPGP, but used in the LibrePGP fork.
    /// Signals support for GnuPG-specific "OCB" encryption packet format.
    #[bits(1)]
    _libre_ocb: u8,

    /// Not standardized in OpenPGP, but used in the LibrePGP fork.
    /// Semantics unclear.
    #[bits(1)]
    _libre_v5_keys: u8,

    /// Support for "Version 2 Symmetrically Encrypted and Integrity Protected Data packet"
    #[bits(1)]
    seipd_v2: bool,

    #[bits(4)]
    _padding: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Notation {
    pub readable: bool,
    pub name: Bytes,
    pub value: Bytes,
}

/// Codes for revocation reasons
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum RevocationCode {
    /// No reason specified (key revocations or cert revocations)
    NoReason = 0,
    /// Key is superseded (key revocations)
    KeySuperseded = 1,
    /// Key material has been compromised (key revocations)
    KeyCompromised = 2,
    /// Key is retired and no longer used (key revocations)
    KeyRetired = 3,
    /// User ID information is no longer valid (cert revocations)
    CertUserIdInvalid = 32,

    /// Private Use range (from OpenPGP)
    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    /// Undefined code
    #[num_enum(catch_all)]
    Other(u8),
}

impl PacketTrait for Signature {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

pub(super) fn serialize_for_hashing<K: KeyDetails + Serialize>(
    key: &K,
    hasher: &mut Box<dyn DynDigest + Send>,
) -> Result<()> {
    let key_len = key.write_len();

    let mut writer = WriteHasher(hasher);

    // old style packet header for the key
    match key.version() {
        KeyVersion::V2 | KeyVersion::V3 | KeyVersion::V4 => {
            // When a v4 signature is made over a key, the hash data starts with the octet 0x99,
            // followed by a two-octet length of the key, and then the body of the key packet.
            writer.write_u8(0x99)?;
            writer.write_u16::<BigEndian>(key_len.try_into()?)?;
        }

        KeyVersion::V6 => {
            // When a v6 signature is made over a key, the hash data starts with the salt
            // [NOTE: the salt is hashed in packet/signature/config.rs],

            // then octet 0x9B, followed by a four-octet length of the key,
            // and then the body of the key packet.
            writer.write_u8(0x9b)?;
            writer.write_u32::<BigEndian>(key_len.try_into()?)?;
        }

        v => unimplemented_err!("key version {:?}", v),
    }

    key.to_writer(&mut writer)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::packet::SubpacketType;

    /// keyflags being all zeros..are special
    #[test]
    fn test_keyflags_crazy_versions() {
        for i in 0..1024 {
            println!("size {}", i);
            // I write this with pain...
            let source = BytesMut::zeroed(i).freeze();
            let flags = KeyFlags::try_from_reader(&source[..]).unwrap();
            assert_eq!(&flags.to_bytes().unwrap(), &source);
        }
    }

    #[test]
    fn test_keyflags_1_byte() {
        let flags: KeyFlags = Default::default();
        assert_eq!(flags.to_bytes().unwrap(), vec![0x00]);

        let mut flags = KeyFlags::default();
        flags.set_certify(true);
        assert!(flags.certify());
        assert_eq!(flags.to_bytes().unwrap(), vec![0x01]);

        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x02]);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x04]);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_storage(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x08]);

        let mut flags = KeyFlags::default();
        flags.set_shared(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x10]);

        let mut flags = KeyFlags::default();
        flags.set_authentication(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x20]);

        let mut flags = KeyFlags::default();
        flags.set_group(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x80]);

        let mut flags = KeyFlags::default();
        flags.set_certify(true);
        flags.set_sign(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x03]);
    }

    #[test]
    fn test_keyflags_2_bytes() {
        let mut flags: KeyFlags = Default::default();
        flags.set_adsk(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x00, 0x04]);

        let mut flags: KeyFlags = Default::default();
        flags.set_timestamping(true);
        assert_eq!(flags.to_bytes().unwrap(), vec![0x00, 0x08]);

        let mut flags: KeyFlags = Default::default();
        flags.set_timestamping(true);
        flags.set_certify(true);
        flags.set_sign(true);

        assert_eq!(flags.to_bytes().unwrap(), vec![0x03, 0x08]);
    }

    #[test]
    fn test_features() {
        use crate::packet::Features;

        // deserialize/serialize, getters
        {
            let empty: Features = (&[][..]).into();
            assert_eq!(empty.seipd_v1(), false);
            assert_eq!(empty.seipd_v2(), false);

            assert_eq!(empty.write_len(), 0);
            let mut out = vec![];
            empty.to_writer(&mut out).expect("write");
            assert!(out.is_empty());
        }
        {
            let seipdv1: Features = (&[0x01][..]).into();
            assert_eq!(seipdv1.seipd_v1(), true);
            assert_eq!(seipdv1.seipd_v2(), false);

            assert_eq!(seipdv1.write_len(), 1);
            let mut out = vec![];
            seipdv1.to_writer(&mut out).expect("write");
            assert_eq!(out, vec![0x01]);
        }
        {
            let allbits: Features = (&[0xff][..]).into();
            assert_eq!(allbits.seipd_v1(), true);
            assert_eq!(allbits.seipd_v2(), true);

            assert_eq!(allbits.write_len(), 1);
            let mut out = vec![];
            allbits.to_writer(&mut out).expect("write");
            assert_eq!(out, vec![0xff]);
        }
        {
            let three_bytes: Features = (&[0x09, 0xaa, 0xbb][..]).into();
            assert_eq!(three_bytes.seipd_v1(), true);
            assert_eq!(three_bytes.seipd_v2(), true);

            assert_eq!(three_bytes.write_len(), 3);
            let mut out = vec![];
            three_bytes.to_writer(&mut out).expect("write");
            assert_eq!(out, vec![0x09, 0xaa, 0xbb]);
        }

        // setters
        {
            let mut empty: Features = (&[][..]).into();
            assert!(Vec::<u8>::from(&empty).is_empty());

            empty.set_seipd_v1(true);
            assert_eq!(Vec::<u8>::from(&empty), vec![0x01]);
        }
        {
            let mut default = Features::default();
            assert_eq!(Vec::<u8>::from(&default), vec![0x00]);

            default.set_seipd_v1(true);
            assert_eq!(Vec::<u8>::from(&default), vec![0x01]);

            default.set_seipd_v2(true);
            assert_eq!(Vec::<u8>::from(&default), vec![0x09]);
        }
        {
            let mut allbits: Features = (&[0xff][..]).into();

            allbits.set_seipd_v1(false);
            assert_eq!(Vec::<u8>::from(&allbits), vec![0xfe]);

            allbits.set_seipd_v2(false);
            assert_eq!(Vec::<u8>::from(&allbits), vec![0xf6]);
        }
        {
            let mut three_bytes: Features = (&[0x00, 0xaa, 0xbb][..]).into();
            three_bytes.set_seipd_v2(true);
            assert_eq!(Vec::<u8>::from(&three_bytes), vec![0x08, 0xaa, 0xbb]);
        }
    }

    #[test]
    fn test_critical() {
        use SubpacketType::*;
        let cases = [
            SignatureCreationTime,
            SignatureExpirationTime,
            ExportableCertification,
            TrustSignature,
            RegularExpression,
            Revocable,
            KeyExpirationTime,
            PreferredSymmetricAlgorithms,
            RevocationKey,
            Issuer,
            Notation,
            PreferredHashAlgorithms,
            PreferredCompressionAlgorithms,
            KeyServerPreferences,
            PreferredKeyServer,
            PrimaryUserId,
            PolicyURI,
            KeyFlags,
            SignersUserID,
            RevocationReason,
            Features,
            SignatureTarget,
            EmbeddedSignature,
            IssuerFingerprint,
            PreferredAead,
            Experimental(101),
            Other(95),
        ];
        for case in cases {
            assert_eq!(SubpacketType::from_u8(case.as_u8(false)), (case, false));
            assert_eq!(SubpacketType::from_u8(case.as_u8(true)), (case, true));
        }
    }

    use proptest::prelude::*;

    impl Arbitrary for KeyFlags {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            proptest::collection::vec(0u8..255, 1..500)
                .prop_map(|v| KeyFlags::try_from_reader(&mut &v[..]).unwrap())
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn keyflags_write_len(flags: KeyFlags) {
            let mut buf = Vec::new();
            flags.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), flags.write_len());
        }

        #[test]
        fn keyflags_packet_roundtrip(flags: KeyFlags) {
            let mut buf = Vec::new();
            flags.to_writer(&mut buf).unwrap();
            let new_flags = KeyFlags::try_from_reader(&mut &buf[..]).unwrap();
            prop_assert_eq!(flags, new_flags);
        }
    }
}
