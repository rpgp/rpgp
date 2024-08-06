use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use log::debug;
use rand::{CryptoRng, Rng};

use crate::crypto::hash::{HashAlgorithm, Hasher};
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{Signature, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use crate::ser::Serialize;
use crate::types::{Fingerprint, KeyId, PublicKeyTrait, SecretKeyTrait, Tag};

#[derive(Clone, PartialEq, Eq, Debug, Builder)]
#[builder(build_fn(error = "Error"))]
pub struct SignatureConfig {
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,

    pub version_specific: SignatureVersionSpecific,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignatureVersionSpecific {
    // specific to V2 and V3 signatures
    V3 {
        created: DateTime<Utc>,
        issuer: KeyId,
    },
    V4 {},
    V6 {
        salt: Vec<u8>,
    },
}

impl SignatureConfig {
    pub fn new_v4(
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        // FIXME: must not be called for v6 signatures

        SignatureConfig {
            version,
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets,
            unhashed_subpackets,
            version_specific: SignatureVersionSpecific::V4 {},
        }
    }

    pub fn version_specific<R>(
        mut rng: &mut R,
        version: SignatureVersion,
        hash_alg: HashAlgorithm,
    ) -> Result<SignatureVersionSpecific>
    where
        R: CryptoRng + Rng,
    {
        match version {
            SignatureVersion::V6 => Ok(SignatureVersionSpecific::V6 {
                salt: crate::types::salt_for(&mut rng, hash_alg),
            }),
            SignatureVersion::V4 => Ok(SignatureVersionSpecific::V4 {}),
            _ => bail!("Unsupported signature version {:version?}"),
        }
    }

    pub fn new_v4_v6<R>(
        mut rng: &mut R,
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Result<Self>
    where
        R: CryptoRng + Rng,
    {
        Ok(SignatureConfig {
            version,
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets,
            unhashed_subpackets,
            version_specific: Self::version_specific(&mut rng, version, hash_alg)?,
        })
    }

    /// Sign the given data.
    pub fn sign<F, R>(self, key: &impl SecretKeyTrait, key_pw: F, data: R) -> Result<Signature>
    where
        F: FnOnce() -> String,
        R: Read,
    {
        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        self.hash_data_to_sign(&mut *hasher, data)?;
        let len = self.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Create a certification self-signature.
    pub fn sign_certification<F>(
        self,
        key: &impl SecretKeyTrait,
        key_pw: F,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.sign_certification_third_party(key, key_pw, key, tag, id)
    }

    /// Create a certification third-party signature.
    pub fn sign_certification_third_party<F>(
        self,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        ensure!(
            self.is_certification(),
            "can not sign non certification as certification"
        );
        debug!("signing certification {:#?}", self.typ);

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        signee.serialize_for_hashing(&mut hasher)?;

        let mut packet_buf = Vec::new();
        id.to_writer(&mut packet_buf)?;

        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let prefix = match tag {
                    Tag::UserId => 0xB4,
                    Tag::UserAttribute => 0xD1,
                    _ => bail!("invalid tag for certification signature: {:?}", tag),
                };

                let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len() as u32);

                // prefixes
                hasher.update(&prefix_buf);
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported sign tps")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }

        // the packet content
        hasher.update(&packet_buf);

        let len = self.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.create_signature(signer_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Sign a key binding.
    pub fn sign_key_binding<F>(
        self,
        signing_key: &impl SecretKeyTrait,
        key_pw: F,
        key: &impl PublicKeyTrait,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        debug!(
            "signing key binding: {:#?} - {:#?} - {:#?}",
            self, signing_key, key
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        // Signing Key
        signing_key.serialize_for_hashing(&mut hasher)?;

        // Key being bound
        key.serialize_for_hashing(&mut hasher)?;

        let len = self.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Signs a direct key signature or a revocation.
    pub fn sign_key<F>(
        self,
        signing_key: &impl SecretKeyTrait,
        key_pw: F,
        key: &impl PublicKeyTrait,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        debug!("signing key (revocation): {:#?} - {:#?}", self, key);

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        key.serialize_for_hashing(&mut hasher)?;

        let len = self.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Calculate the serialized version of this packet, but only the part relevant for hashing.
    pub fn hash_signature_data(&self, hasher: &mut dyn Hasher) -> Result<usize> {
        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let created = {
                    if let SignatureVersionSpecific::V3 { created, .. } = self.version_specific {
                        created
                    } else {
                        bail!("must exist for a v3 signature")
                    }
                };

                let mut buf = [0u8; 5];
                buf[0] = self.typ.into();
                BigEndian::write_u32(&mut buf[1..], created.timestamp() as u32);

                hasher.update(&buf);

                // no trailer
                Ok(0)
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                // TODO: reduce duplication with serialization code

                let mut res = vec![
                    // the signature version
                    self.version.into(),
                    // the signature type
                    self.typ.into(),
                    // the public-key algorithm
                    self.pub_alg.into(),
                    // the hash algorithm
                    self.hash_alg.into(),
                ];

                // hashed subpackets
                let mut hashed_subpackets = Vec::new();
                for packet in &self.hashed_subpackets {
                    debug!("hashing {:#?}", packet);
                    packet.to_writer(&mut hashed_subpackets)?;
                }

                // append hashed area length, as u16 for v4, and u32 for v6
                if self.version == SignatureVersion::V4 {
                    res.extend(u16::try_from(hashed_subpackets.len())?.to_be_bytes());
                } else if self.version == SignatureVersion::V6 {
                    res.extend(u32::try_from(hashed_subpackets.len())?.to_be_bytes());
                }

                res.extend(hashed_subpackets);

                hasher.update(&res);

                Ok(res.len())
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported hash data")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    pub fn hash_data_to_sign<R>(&self, hasher: &mut dyn Hasher, mut data: R) -> Result<usize>
    where
        R: Read,
    {
        match self.typ {
            SignatureType::Text |
                // assumes that the passed in text was already valid utf8 and normalized
            SignatureType::Binary => {
                Ok(std::io::copy(&mut data, hasher)? as usize)
            }
            SignatureType::Timestamp |
            SignatureType::Standalone => {
                let mut val = [0u8;1];
                data.read_exact(&mut val[..])?;
                hasher.update(&val[..]);
                Ok(1)
            }
            SignatureType::CertGeneric
            | SignatureType::CertPersona
            | SignatureType::CertCasual
            | SignatureType::CertPositive
            | SignatureType::CertRevocation => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::SubkeyBinding
            | SignatureType::SubkeyRevocation
            | SignatureType::KeyBinding
            | SignatureType::Key => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::KeyRevocation => unimplemented_err!("KeyRevocation"),
            SignatureType::ThirdParty => unimplemented_err!("signing ThirdParty"),

            SignatureType::Other(id) => unimplemented_err!("Other ({})", id),
        }
    }

    pub fn trailer(&self, len: usize) -> Result<Vec<u8>> {
        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
                Ok(Vec::new())
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut trailer = vec![self.version.into(), 0xFF, 0, 0, 0, 0];
                BigEndian::write_u32(&mut trailer[2..], len as u32);
                Ok(trailer)
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    /// Returns an iterator of all subpackets in the signature: all subpackets in the hashed area
    /// followed by all subpackets in the unhashed area.
    #[deprecated(
        note = "Usually only hashed_subpackets should be used. unhashed_subpackets are only safe and useful to access in rare circumstances. When they are needed, unhashed_subpackets should be explicitly called."
    )]
    pub fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets().chain(self.unhashed_subpackets())
    }

    /// Returns an iterator over the hashed subpackets of this signature.
    pub fn hashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets.iter()
    }

    /// Returns an iterator over the unhashed subpackets of this signature.
    pub fn unhashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.unhashed_subpackets.iter()
    }

    /// Returns if the signature is a certification or not.
    pub fn is_certification(&self) -> bool {
        matches!(
            self.typ,
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
                | SignatureType::CertRevocation
        )
    }

    /// Signature Creation Time.
    ///
    /// The time the signature was made.
    /// MUST be present in the hashed area.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.4
    ///
    /// Returns the first Signature Creation Time subpacket, only from the hashed area.
    pub fn created(&self) -> Option<&DateTime<Utc>> {
        if let SignatureVersionSpecific::V3 { created, .. } = &self.version_specific {
            return Some(created);
        }

        self.hashed_subpackets().find_map(|p| match p.data {
            SubpacketData::SignatureCreationTime(ref d) => Some(d),
            _ => None,
        })
    }

    /// Issuer.
    ///
    /// The OpenPGP Key ID of the key issuing the signature.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.5
    ///
    /// Returns Issuer subpacket data from both the hashed and unhashed area.
    pub fn issuer(&self) -> Vec<&KeyId> {
        // legacy v2/v3 signatures have an explicit "issuer" field
        if let SignatureVersionSpecific::V3 { issuer, .. } = &self.version_specific {
            return vec![issuer];
        }

        // v4+ signatures use subpackets
        //
        // We consider data from both the hashed and unhashed area here, because the issuer Key ID
        // only acts as a hint. The signature will be cryptographically checked using the purported
        // issuer's key material. An attacker cannot successfully claim an issuer Key ID that they
        // can't produce a cryptographically valid signature for.
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match sp.data {
                SubpacketData::Issuer(ref id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Issuer Fingerprint.
    ///
    /// The OpenPGP Key fingerprint of the key issuing the signature.
    ///
    /// This subpacket type was introduced after RFC 4880, in the RFC 4880-bis lifecycle.
    /// It sees some use in the wild for v4 signatures, in both the hashed and unhashed areas.
    ///
    /// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#name-issuer-fingerprint
    ///
    /// Returns Issuer Fingerprint subpacket data from both the hashed and unhashed area.
    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match &sp.data {
                SubpacketData::IssuerFingerprint(fp) => Some(fp),
                _ => None,
            })
            .collect()
    }
}
