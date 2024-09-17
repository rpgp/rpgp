use std::io::Read;

use bitfield::bitfield;
use bstr::{BStr, BString};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Duration, Utc};
use iter_read::IterRead;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use smallvec::{smallvec, SmallVec};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::line_writer::LineBreak;
use crate::normalize_lines::Normalized;
use crate::packet::signature::SignatureConfig;
use crate::packet::{PacketTrait, SignatureVersionSpecific};
use crate::ser::Serialize;
use crate::types::{
    self, CompressionAlgorithm, Fingerprint, KeyId, PublicKeyTrait, SignatureBytes, Tag, Version,
};

/// Signature Packet
/// <https://tools.ietf.org/html/rfc4880.html#section-5.2>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Signature {
    packet_version: Version,

    pub config: SignatureConfig,
    #[debug("{}", hex::encode(signed_hash_value))]
    pub signed_hash_value: [u8; 2],
    pub signature: SignatureBytes,
}

impl Signature {
    /// Constructor for an OpenPGP v2 signature packet.
    /// Note: This is a historical packet version!
    #[allow(clippy::too_many_arguments)]
    pub fn v2(
        packet_version: Version,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_version,
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
        }
    }

    /// Constructor for an OpenPGP v3 signature packet.
    /// Note: This is a historical packet version!
    #[allow(clippy::too_many_arguments)]
    pub fn v3(
        packet_version: Version,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_version,
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
        }
    }

    /// Constructor for an OpenPGP v4 signature packet.
    ///
    /// OpenPGP v4 signatures are typically used with OpenPGP v4 keys, as specified in RFC 4880
    /// (and 2440).
    #[allow(clippy::too_many_arguments)]
    pub fn v4(
        packet_version: Version,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        Signature {
            packet_version,
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
        }
    }

    /// Constructor for an OpenPGP v6 signature packet.
    ///
    /// OpenPGP v6 signatures are specified in RFC 9580 and only used with OpenPGP v6 keys.
    #[allow(clippy::too_many_arguments)]
    pub fn v6(
        packet_version: Version,
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
            packet_version,
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
        }
    }

    pub fn from_config(
        config: SignatureConfig,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_version: Default::default(),
            config,
            signed_hash_value,
            signature,
        }
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.config.typ()
    }

    /// The used `HashAlgorithm`.
    pub fn hash_alg(&self) -> HashAlgorithm {
        self.config.hash_alg
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

    /// Verify this signature.
    pub fn verify<R>(&self, key: &impl PublicKeyTrait, data: R) -> Result<()>
    where
        R: Read,
    {
        ensure!(
            Self::match_identity(self, key),
            "verify: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            &key.key_id(),
        );

        let mut hasher = self.config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.config.version_specific {
            hasher.update(salt.as_ref())
        }

        if matches!(self.typ(), SignatureType::Text) {
            let normalized = Normalized::new(data.bytes().flat_map(|b| b.ok()), LineBreak::Crlf);

            self.config
                .hash_data_to_sign(&mut *hasher, IterRead::new(normalized))?;
        } else {
            self.config.hash_data_to_sign(&mut *hasher, data)?;
        }
        let len = self.config.hash_signature_data(&mut hasher)?;
        hasher.update(&self.config.trailer(len)?);

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "signature: invalid signed hash value"
        );

        key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a certification signature type (for self-signatures).
    pub fn verify_certification(
        &self,
        key: &impl PublicKeyTrait,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<()> {
        self.verify_third_party_certification(&key, &key, tag, id)
    }

    /// Verifies a certification signature type (for third-party signatures).
    pub fn verify_third_party_certification(
        &self,
        signee: &impl PublicKeyTrait,
        signer: &impl PublicKeyTrait,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<()> {
        let key_id = signee.key_id();
        debug!("verifying certification {:?} {:#?}", key_id, self);

        ensure!(
            Self::match_identity(self, signer),
            "verify_certification: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            key_id,
        );

        let mut hasher = self.config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.config.version_specific {
            hasher.update(salt.as_ref())
        }

        // the key of the signee
        {
            let mut key_buf = Vec::new();
            // TODO: this is different for V5
            signee.serialize_for_hashing(&mut key_buf)?;
            hasher.update(&key_buf);
        }

        // the packet content
        {
            let mut packet_buf = Vec::new();
            id.to_writer(&mut packet_buf)?;

            match self.config.version() {
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
                    BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len().try_into()?);

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

            hasher.update(&packet_buf);
        }

        let len = self.config.hash_signature_data(&mut hasher)?;
        hasher.update(&self.config.trailer(len)?);

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "certification: invalid signed hash value"
        );

        signer.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a key binding (which binds a subkey to the primary key).
    ///
    /// "Subkey Binding Signature (type ID 0x18)"
    pub fn verify_key_binding(
        &self,
        signing_key: &impl PublicKeyTrait,
        key: &impl PublicKeyTrait,
    ) -> Result<()> {
        self.verify_key_binding_internal(signing_key, key, false)
    }

    /// Verifies a primary key binding signature, or "back signature" (which links the primary to a signing subkey).
    ///
    /// "Primary Key Binding Signature (type ID 0x19)"
    pub fn verify_backwards_key_binding(
        &self,
        signing_key: &impl PublicKeyTrait,
        key: &impl PublicKeyTrait,
    ) -> Result<()> {
        self.verify_key_binding_internal(signing_key, key, true)
    }

    /// Verify subkey binding signatures, either regular subkey binding, or a "back signature".
    ///
    /// - when backsig is false: verify a "Subkey Binding Signature (type ID 0x18)"
    /// - when backsig is true: verify a "Primary Key Binding Signature (type ID 0x19)"
    fn verify_key_binding_internal(
        &self,
        signer: &impl PublicKeyTrait,
        signee: &impl PublicKeyTrait,
        backsig: bool,
    ) -> Result<()> {
        debug!(
            "verifying key binding: {:#?} - {:#?} - {:#?} (backsig: {})",
            self, signer, signee, backsig
        );

        let mut hasher = self.config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.config.version_specific {
            hasher.update(salt.as_ref())
        }

        // Hash the two keys:
        // - for a regular binding signature, first the signer (primary), then the signee (subkey)
        // - for a "backward signature" (Primary Key Binding Signature), the order of hashing is signee (primary), signer (subkey)

        // First key to hash
        {
            let mut key_buf = Vec::new();
            if !backsig {
                signer.serialize_for_hashing(&mut key_buf)?; // primary
            } else {
                signee.serialize_for_hashing(&mut key_buf)?; // primary
            }

            hasher.update(&key_buf);
        }
        // Second key to hash
        {
            let mut key_buf = Vec::new();
            if !backsig {
                signee.serialize_for_hashing(&mut key_buf)?; // subkey
            } else {
                signer.serialize_for_hashing(&mut key_buf)?; // subkey
            }

            hasher.update(&key_buf);
        }

        let len = self.config.hash_signature_data(&mut hasher)?;
        hasher.update(&self.config.trailer(len)?);

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "key binding: invalid signed hash value"
        );

        signer.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a direct key signature or a revocation.
    pub fn verify_key(&self, key: &impl PublicKeyTrait) -> Result<()> {
        debug!("verifying key (revocation): {:#?} - {:#?}", self, key);

        ensure!(
            Self::match_identity(self, key),
            "verify_key: No matching issuer or issuer_fingerprint for Key ID: {:?}",
            &key.key_id(),
        );

        let mut hasher = self.config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.config.version_specific {
            hasher.update(salt.as_ref())
        }

        {
            let mut key_buf = Vec::new();
            key.serialize_for_hashing(&mut key_buf)?;

            hasher.update(&key_buf);
        }

        let len = self.config.hash_signature_data(&mut hasher)?;
        hasher.update(&self.config.trailer(len)?);

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "key: invalid signed hash value"
        );

        key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Returns if the signature is a certification or not.
    pub fn is_certification(&self) -> bool {
        self.config.is_certification()
    }

    pub fn key_expiration_time(&self) -> Option<&Duration> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::KeyExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn signature_expiration_time(&self) -> Option<&Duration> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::SignatureExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn created(&self) -> Option<&DateTime<Utc>> {
        self.config.created()
    }

    pub fn issuer(&self) -> Vec<&KeyId> {
        self.config.issuer()
    }

    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.config.issuer_fingerprint()
    }

    pub fn preferred_symmetric_algs(&self) -> &[SymmetricKeyAlgorithm] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::PreferredSymmetricAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_aead_algs(&self) -> &[(SymmetricKeyAlgorithm, AeadAlgorithm)] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::PreferredAeadAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_hash_algs(&self) -> &[HashAlgorithm] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::PreferredHashAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_compression_algs(&self) -> &[CompressionAlgorithm] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::PreferredCompressionAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_server_prefs(&self) -> &[u8] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::KeyServerPreferences(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_flags(&self) -> KeyFlags {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::KeyFlags(d) => Some(d[..].into()),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn features(&self) -> &[u8] {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::Features(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn revocation_reason_code(&self) -> Option<&RevocationCode> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::RevocationReason(code, _) => Some(code),
            _ => None,
        })
    }

    pub fn revocation_reason_string(&self) -> Option<&BStr> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::RevocationReason(_, reason) => Some(reason.as_ref()),
            _ => None,
        })
    }

    pub fn is_primary(&self) -> bool {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::IsPrimary(d) => Some(*d),
                _ => None,
            })
            .unwrap_or(false)
    }

    pub fn is_revocable(&self) -> bool {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::Revocable(d) => Some(*d),
                _ => None,
            })
            .unwrap_or(true)
    }

    pub fn embedded_signature(&self) -> Option<&Signature> {
        // We consider data from both the hashed and unhashed area here, because the embedded
        // signature is inherently cryptographically secured. An attacker can't add a valid
        // embedded signature, canonicalization will remove any invalid embedded signature
        // subpackets.
        self.config
            .hashed_subpackets()
            .chain(self.config.unhashed_subpackets())
            .find_map(|p| match &p.data {
                SubpacketData::EmbeddedSignature(d) => Some(&**d),
                _ => None,
            })
    }

    pub fn preferred_key_server(&self) -> Option<&str> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::PreferredKeyServer(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn notations(&self) -> Vec<&Notation> {
        self.config
            .hashed_subpackets()
            .filter_map(|p| match &p.data {
                SubpacketData::Notation(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    pub fn revocation_key(&self) -> Option<&types::RevocationKey> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::RevocationKey(d) => Some(d),
            _ => None,
        })
    }

    /// Gets the user id of the signer
    ///
    /// Note that the user id may not be valid utf-8, if it was created
    /// using a different encoding. But since the RFC describes every
    /// text as utf-8 it is up to the caller whether to error on non utf-8 data.
    pub fn signers_userid(&self) -> Option<&BStr> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::SignersUserID(d) => Some(d.as_ref()),
            _ => None,
        })
    }

    pub fn policy_uri(&self) -> Option<&str> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::PolicyURI(d) => Some(d.as_ref()),
            _ => None,
        })
    }

    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::TrustSignature(depth, value) => Some((*depth, *value)),
            _ => None,
        })
    }

    pub fn regular_expression(&self) -> Option<&BStr> {
        self.config.hashed_subpackets().find_map(|p| match &p.data {
            SubpacketData::RegularExpression(d) => Some(d.as_ref()),
            _ => None,
        })
    }

    pub fn exportable_certification(&self) -> bool {
        self.config
            .hashed_subpackets()
            .find_map(|p| match &p.data {
                SubpacketData::ExportableCertification(d) => Some(*d),
                _ => None,
            })
            .unwrap_or(true)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Default for SignatureVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
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
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Available signature subpacket types
pub enum SubpacketType {
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
    PreferredEncryptionModes, // non-RFC, may only be 1: EAX, 2: OCB
    IntendedRecipientFingerprint,
    // AttestedCertifications, // non-RFC
    // KeyBlock,               // non-RFC
    PreferredAead,
    Experimental(u8),
    Other(u8),
}

impl SubpacketType {
    pub fn as_u8(&self, is_critical: bool) -> u8 {
        let raw: u8 = match self {
            SubpacketType::SignatureCreationTime => 2,
            SubpacketType::SignatureExpirationTime => 3,
            SubpacketType::ExportableCertification => 4,
            SubpacketType::TrustSignature => 5,
            SubpacketType::RegularExpression => 6,
            SubpacketType::Revocable => 7,
            SubpacketType::KeyExpirationTime => 9,
            SubpacketType::PreferredSymmetricAlgorithms => 11,
            SubpacketType::RevocationKey => 12,
            SubpacketType::Issuer => 16,
            SubpacketType::Notation => 20,
            SubpacketType::PreferredHashAlgorithms => 21,
            SubpacketType::PreferredCompressionAlgorithms => 22,
            SubpacketType::KeyServerPreferences => 23,
            SubpacketType::PreferredKeyServer => 24,
            SubpacketType::PrimaryUserId => 25,
            SubpacketType::PolicyURI => 26,
            SubpacketType::KeyFlags => 27,
            SubpacketType::SignersUserID => 28,
            SubpacketType::RevocationReason => 29,
            SubpacketType::Features => 30,
            SubpacketType::SignatureTarget => 31,
            SubpacketType::EmbeddedSignature => 32,
            SubpacketType::IssuerFingerprint => 33,
            SubpacketType::PreferredEncryptionModes => 34,
            SubpacketType::IntendedRecipientFingerprint => 35,
            // SubpacketType::AttestedCertifications => 37,
            // SubpacketType::KeyBlock => 38,
            SubpacketType::PreferredAead => 39,
            SubpacketType::Experimental(n) => *n,
            SubpacketType::Other(n) => *n,
        };

        if is_critical {
            // set critical bit
            raw | 0b1000_0000
        } else {
            raw
        }
    }

    #[inline]
    pub fn from_u8(n: u8) -> (Self, bool) {
        let is_critical = (n >> 7) == 1;
        // remove critical bit
        let n = n & 0b0111_1111;

        let m = match n {
            2 => SubpacketType::SignatureCreationTime,
            3 => SubpacketType::SignatureExpirationTime,
            4 => SubpacketType::ExportableCertification,
            5 => SubpacketType::TrustSignature,
            6 => SubpacketType::RegularExpression,
            7 => SubpacketType::Revocable,
            9 => SubpacketType::KeyExpirationTime,
            11 => SubpacketType::PreferredSymmetricAlgorithms,
            12 => SubpacketType::RevocationKey,
            16 => SubpacketType::Issuer,
            20 => SubpacketType::Notation,
            21 => SubpacketType::PreferredHashAlgorithms,
            22 => SubpacketType::PreferredCompressionAlgorithms,
            23 => SubpacketType::KeyServerPreferences,
            24 => SubpacketType::PreferredKeyServer,
            25 => SubpacketType::PrimaryUserId,
            26 => SubpacketType::PolicyURI,
            27 => SubpacketType::KeyFlags,
            28 => SubpacketType::SignersUserID,
            29 => SubpacketType::RevocationReason,
            30 => SubpacketType::Features,
            31 => SubpacketType::SignatureTarget,
            32 => SubpacketType::EmbeddedSignature,
            33 => SubpacketType::IssuerFingerprint,
            34 => SubpacketType::PreferredEncryptionModes,
            35 => SubpacketType::IntendedRecipientFingerprint,
            // 37 => SubpacketType::AttestedCertifications,
            // 38 => SubpacketType::KeyBlock,
            39 => SubpacketType::PreferredAead,
            100..=110 => SubpacketType::Experimental(n),
            _ => SubpacketType::Other(n),
        };

        (m, is_critical)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subpacket {
    pub is_critical: bool,
    pub data: SubpacketData,
}

impl Subpacket {
    /// Construct a new regular subpacket.
    pub const fn regular(data: SubpacketData) -> Self {
        Subpacket {
            is_critical: false,
            data,
        }
    }

    /// Construct a new critical subpacket.
    pub const fn critical(data: SubpacketData) -> Self {
        Subpacket {
            is_critical: true,
            data,
        }
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum SubpacketData {
    /// The time the signature was made.
    SignatureCreationTime(DateTime<Utc>),
    /// The time the signature will expire.
    SignatureExpirationTime(Duration),
    /// When the key is going to expire
    KeyExpirationTime(Duration),
    /// The OpenPGP Key ID of the key issuing the signature.
    Issuer(KeyId),
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    /// Renamed to "Preferred Symmetric Ciphers for v1 SEIPD" in RFC 9580
    PreferredSymmetricAlgorithms(SmallVec<[SymmetricKeyAlgorithm; 8]>),
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    PreferredHashAlgorithms(SmallVec<[HashAlgorithm; 8]>),
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    PreferredCompressionAlgorithms(SmallVec<[CompressionAlgorithm; 8]>),
    KeyServerPreferences(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 4]>),
    KeyFlags(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 1]>),
    Features(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 1]>),
    RevocationReason(RevocationCode, BString),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(Notation),
    RevocationKey(types::RevocationKey),
    SignersUserID(BString),
    /// The URI of the policy under which the signature was issued
    PolicyURI(String),
    TrustSignature(u8, u8),
    RegularExpression(BString),
    ExportableCertification(bool),
    IssuerFingerprint(Fingerprint),
    PreferredEncryptionModes(SmallVec<[AeadAlgorithm; 2]>),
    IntendedRecipientFingerprint(Fingerprint),
    PreferredAeadAlgorithms(SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>),
    Experimental(u8, #[debug("{}", hex::encode(_1))] SmallVec<[u8; 2]>),
    Other(u8, #[debug("{}", hex::encode(_1))] Vec<u8>),
    SignatureTarget(
        PublicKeyAlgorithm,
        HashAlgorithm,
        #[debug("{}", hex::encode(_2))] Vec<u8>,
    ),
}

bitfield! {
    #[derive(Default, PartialEq, Eq, Copy, Clone)]
    pub struct KeyFlags(u8);
    impl Debug;

    pub certify, set_certify: 0;
    pub sign, set_sign: 1;
    pub encrypt_comms, set_encrypt_comms: 2;
    pub encrypt_storage, set_encrypt_storage: 3;
    pub shared, set_shared: 4;
    pub authentication, set_authentication: 5;
    pub group, set_group: 7;
}

impl<'a> From<&'a [u8]> for KeyFlags {
    fn from(other: &'a [u8]) -> Self {
        if other.is_empty() {
            Default::default()
        } else {
            KeyFlags(other[0])
        }
    }
}

impl From<KeyFlags> for SmallVec<[u8; 1]> {
    fn from(flags: KeyFlags) -> Self {
        smallvec![flags.0]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Notation {
    pub readable: bool,
    pub name: BString,
    pub value: BString,
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
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyflags() {
        let flags: KeyFlags = Default::default();
        assert_eq!(flags.0, 0x00);

        let mut flags = KeyFlags::default();
        flags.set_certify(true);
        assert!(flags.certify());
        assert_eq!(flags.0, 0x01);

        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        assert_eq!(flags.0, 0x02);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        assert_eq!(flags.0, 0x04);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_storage(true);
        assert_eq!(flags.0, 0x08);

        let mut flags = KeyFlags::default();
        flags.set_shared(true);
        assert_eq!(flags.0, 0x10);

        let mut flags = KeyFlags::default();
        flags.set_authentication(true);
        assert_eq!(flags.0, 0x20);

        let mut flags = KeyFlags::default();
        flags.set_group(true);
        assert_eq!(flags.0, 0x80);
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
}
