use std::fmt;
use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};

use crate::crypto::hash::{HashAlgorithm, Hasher};
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{Signature, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use crate::ser::Serialize;
use crate::types::{KeyId, PublicKeyTrait, SecretKeyTrait, Tag};

#[derive(Clone, PartialEq, Eq, Builder)]
#[builder(build_fn(error = "Error"))]
pub struct SignatureConfig {
    #[builder(default)]
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,

    #[builder(default)]
    pub hash_alg: HashAlgorithm,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,

    // only set on V2 and V3 keys
    #[builder(default)]
    pub created: Option<DateTime<Utc>>,
    #[builder(default)]
    pub issuer: Option<KeyId>,
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
        SignatureConfig {
            version,
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets,
            unhashed_subpackets,
            issuer: None,
            created: None,
        }
    }

    /// Sign the given data.
    pub fn sign<F, R>(self, key: &impl SecretKeyTrait, key_pw: F, data: R) -> Result<Signature>
    where
        F: FnOnce() -> String,
        R: Read,
    {
        let mut hasher = self.hash_alg.new_hasher()?;

        self.hash_data_to_sign(&mut *hasher, data)?;
        let len = self.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Create a certification siganture.
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
        ensure!(
            self.is_certification(),
            "can not sign non certification as certification"
        );
        debug!("signing certification {:#?}", self.typ);

        let mut hasher = self.hash_alg.new_hasher()?;

        key.to_writer_old(&mut hasher)?;

        let mut packet_buf = Vec::new();
        id.to_writer(&mut packet_buf)?;

        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
            }
            SignatureVersion::V4 | SignatureVersion::V5 => {
                let prefix = match tag {
                    Tag::UserId => 0xB4,
                    Tag::UserAttribute => 0xD1,
                    _ => bail!("invalid tag for certification validation: {:?}", tag),
                };

                let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len() as u32);

                // prefixes
                hasher.update(&prefix_buf);
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
        let signature = key.create_signature(key_pw, self.hash_alg, hash)?;

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

        // Signing Key
        signing_key.to_writer_old(&mut hasher)?;

        // Key being bound
        key.to_writer_old(&mut hasher)?;

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

        key.to_writer_old(&mut hasher)?;

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

    /// Calcluate the serialized version of this packet, but only the part relevant for hashing.
    pub fn hash_signature_data(&self, hasher: &mut dyn Hasher) -> Result<usize> {
        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let mut buf = [0u8; 5];
                buf[0] = self.typ as u8;
                BigEndian::write_u32(
                    &mut buf[1..],
                    self.created
                        .expect("must exist for a v3 signature")
                        .timestamp() as u32,
                );

                hasher.update(&buf);

                // no trailer
                Ok(0)
            }
            SignatureVersion::V4 | SignatureVersion::V5 => {
                // TODO: validate this is the right thing to do for v5
                // TODO: reduce duplication with serialization code

                let mut res = vec![
                    // the signature version
                    self.version.into(),
                    // the signature type
                    self.typ as u8,
                    // the public-key algorithm
                    self.pub_alg.into(),
                    // the hash algorithm
                    self.hash_alg.into(),
                    // will be filled with the length
                    0u8,
                    0u8,
                ];

                // hashed subpackets
                let mut hashed_subpackets = Vec::new();
                for packet in &self.hashed_subpackets {
                    debug!("hashing {:#?}", packet);
                    packet.to_writer(&mut hashed_subpackets)?;
                }

                BigEndian::write_u16(&mut res[4..6], hashed_subpackets.len().try_into()?);
                res.extend(hashed_subpackets);

                hasher.update(&res);

                // TODO: V5 signatures hash additional values here
                // see https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#name-computing-signatures

                Ok(res.len())
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
        }
    }

    pub fn trailer(&self, len: usize) -> Result<Vec<u8>> {
        match self.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
                Ok(Vec::new())
            }
            SignatureVersion::V4 | SignatureVersion::V5 => {
                let mut trailer = vec![0x04, 0xFF, 0, 0, 0, 0];
                BigEndian::write_u32(&mut trailer[2..], len as u32);
                Ok(trailer)
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    /// Returns an iterator over all subpackets of this signature.
    pub fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets
            .iter()
            .chain(self.unhashed_subpackets.iter())
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

    pub fn created(&self) -> Option<&DateTime<Utc>> {
        if self.created.is_some() {
            return self.created.as_ref();
        }

        self.subpackets().find_map(|p| match p.data {
            SubpacketData::SignatureCreationTime(ref d) => Some(d),
            _ => None,
        })
    }

    pub fn issuer(&self) -> Option<&KeyId> {
        if self.issuer.is_some() {
            return self.issuer.as_ref();
        }

        self.subpackets().find_map(|p| match p.data {
            SubpacketData::Issuer(ref id) => Some(id),
            _ => None,
        })
    }
}

impl fmt::Debug for SignatureConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureConfig")
            .field("version", &self.version)
            .field("typ", &self.typ)
            .field("pub_alg", &self.pub_alg)
            .field("hash_alg", &self.hash_alg)
            .field("created", &self.created)
            .field("issuer", &self.issuer)
            .field("unhashed_subpackets", &self.unhashed_subpackets)
            .field("hashed_subpackets", &self.hashed_subpackets)
            .finish()
    }
}
