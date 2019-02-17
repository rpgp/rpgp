use std::time::Duration;

use chrono;
use num_bigint::traits::ModInverse;
use rand::OsRng;
use rsa::{self, PublicKey as PublicKeyTrait};

use composed::{
    SignedKeyDetails, SignedPublicKey, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey,
};
use crypto;
use crypto::ecc_curve::ECCCurve;
use crypto::hash::HashAlgorithm;
use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use crypto::sym::SymmetricKeyAlgorithm;
use errors;
use packet::{
    self, KeyFlags, PacketTrait, SignatureConfigBuilder, SignatureType, Subpacket, UserAttribute,
    UserId,
};
use types::{self, CompressionAlgorithm, KeyTrait, SecretKeyTrait};
use util::{write_bignum_mpi, write_mpi};

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    primary_key: packet::PublicKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
}

/// User facing interface to work with a secret key.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
    secret_subkeys: Vec<SecretSubkey>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyDetails {
    primary_user_id: UserId,
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    keyflags: KeyFlags,
    preferred_symmetric_algorithms: Vec<SymmetricKeyAlgorithm>,
    preferred_hash_algorithms: Vec<HashAlgorithm>,
    preferred_compression_algorithms: Vec<CompressionAlgorithm>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicSubkey {
    key: packet::PublicSubkey,
    keyflags: KeyFlags,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SecretSubkey {
    key: packet::SecretSubkey,
    keyflags: KeyFlags,
}

impl KeyDetails {
    pub fn sign<F>(self, key: &impl SecretKeyTrait, key_pw: F) -> errors::Result<SignedKeyDetails>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let keyflags: Vec<u8> = self.keyflags.into();
        let preferred_symmetric_algorithms = self.preferred_symmetric_algorithms;
        let preferred_hash_algorithms = self.preferred_hash_algorithms;
        let preferred_compression_algorithms = self.preferred_compression_algorithms;

        let mut users = vec![];

        // primary user id
        {
            let id = self.primary_user_id;
            let config = SignatureConfigBuilder::default()
                .typ(SignatureType::CertGeneric)
                .pub_alg(key.algorithm())
                .hashed_subpackets(vec![
                    Subpacket::IsPrimary(true),
                    Subpacket::SignatureCreationTime(chrono::Utc::now()),
                    Subpacket::KeyFlags(keyflags.clone()),
                    Subpacket::PreferredSymmetricAlgorithms(preferred_symmetric_algorithms.clone()),
                    Subpacket::PreferredHashAlgorithms(preferred_hash_algorithms.clone()),
                    Subpacket::PreferredCompressionAlgorithms(
                        preferred_compression_algorithms.clone(),
                    ),
                ])
                .unhashed_subpackets(vec![Subpacket::Issuer(
                    key.key_id().expect("missing key id"),
                )])
                .build()?;

            let sig = config.sign_certificate(key, key_pw.clone(), id.tag(), &id)?;

            users.push(id.into_signed(sig));
        }

        // othe user ids

        users.extend(
            self.user_ids
                .into_iter()
                .map(|id| {
                    let config = SignatureConfigBuilder::default()
                        .typ(SignatureType::CertGeneric)
                        .pub_alg(key.algorithm())
                        .hashed_subpackets(vec![
                            Subpacket::SignatureCreationTime(chrono::Utc::now()),
                            Subpacket::KeyFlags(keyflags.clone()),
                            Subpacket::PreferredSymmetricAlgorithms(
                                preferred_symmetric_algorithms.clone(),
                            ),
                            Subpacket::PreferredHashAlgorithms(preferred_hash_algorithms.clone()),
                            Subpacket::PreferredCompressionAlgorithms(
                                preferred_compression_algorithms.clone(),
                            ),
                        ])
                        .unhashed_subpackets(vec![Subpacket::Issuer(
                            key.key_id().expect("missing key id"),
                        )])
                        .build()?;

                    let sig = config.sign_certificate(key, key_pw.clone(), id.tag(), &id)?;

                    Ok(id.into_signed(sig))
                })
                .collect::<errors::Result<Vec<_>>>()?,
        );

        let user_attributes = self
            .user_attributes
            .into_iter()
            .map(|u| u.sign(key, key_pw.clone()))
            .collect::<errors::Result<Vec<_>>>()?;

        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures: Default::default(),
            users,
            user_attributes,
        })
    }
}

impl PublicKey {
    pub fn sign<F>(
        self,
        sec_key: &mut impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedPublicKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(sec_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(sec_key, key_pw.clone()))
            .collect::<errors::Result<Vec<_>>>()?;

        Ok(SignedPublicKey {
            primary_key,
            details,
            public_subkeys,
        })
    }
}

impl PublicSubkey {
    pub fn sign<F>(
        self,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedPublicSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::SignatureCreationTime(chrono::Utc::now()),
            Subpacket::KeyFlags(self.keyflags.into()),
        ];

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(sec_key.algorithm())
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(vec![Subpacket::Issuer(
                sec_key.key_id().expect("missing key id"),
            )])
            .build()?;

        let signatures = vec![config.sign_key(sec_key, key_pw, &key)?];

        Ok(SignedPublicSubKey { key, signatures })
    }
}

impl SecretKey {
    pub fn sign<F>(self, key_pw: F) -> errors::Result<SignedSecretKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&primary_key, key_pw.clone())?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone()))
            .collect::<errors::Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone()))
            .collect::<errors::Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}

impl SecretSubkey {
    pub fn sign<F>(
        self,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedSecretSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::SignatureCreationTime(chrono::Utc::now()),
            Subpacket::KeyFlags(self.keyflags.into()),
        ];

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(sec_key.algorithm())
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(vec![Subpacket::Issuer(
                sec_key.key_id().expect("missing key id"),
            )])
            .build()?;
        let signatures = vec![config.sign_key_binding(sec_key, key_pw, &key)?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}

#[derive(Debug, PartialEq, Eq, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct SecretKeyParams {
    key_type: KeyType,

    // -- Keyflags
    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_create_certificates: bool,
    #[builder(default)]
    can_encrypt: bool,

    // -- Preferences
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_symmetric_algorithms: Vec<SymmetricKeyAlgorithm>,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_hash_algorithms: Vec<HashAlgorithm>,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_compression_algorithms: Vec<CompressionAlgorithm>,

    #[builder]
    primary_user_id: String,

    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default = "chrono::Utc::now()")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    packet_version: types::Version,
    #[builder(default)]
    version: types::KeyVersion,
    #[builder(default)]
    expiration: Option<Duration>,

    #[builder(default)]
    subkeys: Vec<SubkeyParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Builder)]
pub struct SubkeyParams {
    key_type: KeyType,

    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_create_certificates: bool,
    #[builder(default)]
    can_encrypt: bool,

    #[builder(default)]
    user_ids: Vec<UserId>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default = "chrono::Utc::now()")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    packet_version: types::Version,
    #[builder(default)]
    version: types::KeyVersion,
    #[builder(default)]
    expiration: Option<Duration>,
}

impl SecretKeyParamsBuilder {
    fn validate(&self) -> Result<(), String> {
        match self.key_type {
            Some(KeyType::Rsa(size)) => {
                if size < 2048 {
                    return Err("Keys with less than 2048bits are considered insecure".into());
                }
            }
            Some(KeyType::EdDSA) => {
                if let Some(can_encrypt) = self.can_encrypt {
                    if can_encrypt {
                        return Err("EdDSA can only be used for signing keys".into());
                    }
                }
            }
            Some(KeyType::ECDH) => {
                if let Some(can_sign) = self.can_sign {
                    if can_sign {
                        return Err("ECDH can only be used for encryption keys".into());
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn user_id<VALUE: Into<String>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut user_ids) = self.user_ids {
            user_ids.push(value.into());
        } else {
            self.user_ids = Some(vec![value.into()]);
        }
        self
    }

    pub fn subkey<VALUE: Into<SubkeyParams>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut subkeys) = self.subkeys {
            subkeys.push(value.into());
        } else {
            self.subkeys = Some(vec![value.into()]);
        }
        self
    }
}

impl SecretKeyParams {
    pub fn generate(self) -> errors::Result<SecretKey> {
        let passphrase = self.passphrase;
        let (public_params, secret_params) = self.key_type.generate(passphrase)?;
        let primary_key = packet::SecretKey {
            details: packet::PublicKey {
                packet_version: self.packet_version,
                version: self.version,
                algorithm: self.key_type.to_alg(),
                created_at: self.created_at,
                expiration: self.expiration.map(|v| v.as_secs() as u16),
                public_params,
            },
            secret_params,
        };

        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(self.can_create_certificates);
        keyflags.set_encrypt_comms(self.can_encrypt);
        keyflags.set_encrypt_storage(self.can_encrypt);
        keyflags.set_sign(self.can_sign);

        Ok(SecretKey {
            primary_key,
            details: KeyDetails {
                primary_user_id: UserId::from_str(Default::default(), &self.primary_user_id),
                user_ids: self
                    .user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect(),
                user_attributes: self.user_attributes,
                keyflags,
                preferred_symmetric_algorithms: self.preferred_symmetric_algorithms,
                preferred_hash_algorithms: self.preferred_hash_algorithms,
                preferred_compression_algorithms: self.preferred_compression_algorithms,
            },
            public_subkeys: Default::default(),
            secret_subkeys: self
                .subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let (public_params, secret_params) = subkey.key_type.generate(passphrase)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_certify(subkey.can_create_certificates);
                    keyflags.set_encrypt_comms(subkey.can_encrypt);
                    keyflags.set_encrypt_storage(subkey.can_encrypt);
                    keyflags.set_sign(subkey.can_sign);

                    Ok(SecretSubkey {
                        key: packet::SecretSubkey {
                            details: packet::PublicSubkey {
                                packet_version: subkey.packet_version,
                                version: subkey.version,
                                algorithm: subkey.key_type.to_alg(),
                                created_at: subkey.created_at,
                                expiration: subkey.expiration.map(|v| v.as_secs() as u16),
                                public_params,
                            },
                            secret_params,
                        },
                        keyflags,
                    })
                })
                .collect::<errors::Result<Vec<_>>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// Encryption & Signing with RSA an the given bitsize.
    Rsa(usize),
    /// Encrypting with curev 25519
    ECDH,
    /// Signing with curve 25519
    EdDSA,
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH => PublicKeyAlgorithm::ECDH,
            KeyType::EdDSA => PublicKeyAlgorithm::EdDSA,
        }
    }

    pub fn generate(
        &self,
        passphrase: Option<String>,
    ) -> errors::Result<(PublicParams, types::EncryptedSecretParams)> {
        let mut rng = OsRng::new().expect("no system rng available");

        // TODO: handle encrypt using S2K Iterated and Salted when passphrase is set.
        ensure!(passphrase.is_none(), "Passphrases are note yet supported");

        match self {
            KeyType::Rsa(bit_size) => {
                let key = rsa::RSAPrivateKey::new(&mut rng, *bit_size)?;

                let p = &key.primes()[0];
                let q = &key.primes()[1];
                let u = p
                    .clone()
                    .mod_inverse(q)
                    .expect("invalid prime")
                    .to_biguint()
                    .expect("invalid prime");

                // Data for RSA Public  : [n: MPI, e: MPI]
                // Data for RSA Private : [d: MPI, p: MPI, q: MPI, u: MPI]
                let mut data = Vec::new();
                write_bignum_mpi(key.d(), &mut data)?;
                write_bignum_mpi(p, &mut data)?;
                write_bignum_mpi(q, &mut data)?;
                write_bignum_mpi(&u, &mut data)?;

                let checksum = crypto::checksum::calculate_simple(&data);

                Ok((
                    PublicParams::RSA {
                        n: key.n().clone(),
                        e: key.e().clone(),
                    },
                    types::EncryptedSecretParams::new_plaintext(data, Some(checksum)),
                ))
            }
            KeyType::ECDH => {
                // ECDH could be a different curve, for now it is always ed25519
                let keypair = ed25519_dalek::Keypair::generate(&mut rng);
                let bytes = keypair.to_bytes();

                // secret key
                let q = &bytes[..32];
                // public key
                let mut p = Vec::with_capacity(33);
                p.push(0x40);
                p.extend_from_slice(&bytes[32..]);

                // Data for ECDH Public  : [OID, p: MPI, KDF]
                // Data for ECDH Private : [q: MPI]
                let mut data = Vec::new();
                write_mpi(q, &mut data)?;

                let checksum = crypto::checksum::calculate_simple(&data);

                Ok((
                    PublicParams::ECDH {
                        curve: ECCCurve::Curve25519,
                        p,
                        // TODO: make these configurable and/or check for good defaults
                        hash: HashAlgorithm::SHA512,
                        alg_sym: SymmetricKeyAlgorithm::AES256,
                    },
                    types::EncryptedSecretParams::new_plaintext(data, Some(checksum)),
                ))
            }
            KeyType::EdDSA => {
                let keypair = ed25519_dalek::Keypair::generate(&mut rng);
                let bytes = keypair.to_bytes();

                // secret key
                let p = &bytes[..32];
                // public key
                let mut q = Vec::with_capacity(33);
                q.push(0x40);
                q.extend_from_slice(&bytes[32..]);

                // Data for EdDSA Public  : [OID, q: MPI]
                // Data for EdDSA Private : [p: MPI]
                let mut data = Vec::new();
                write_mpi(p, &mut data)?;

                let checksum = crypto::checksum::calculate_simple(&data);

                Ok((
                    PublicParams::EdDSA {
                        curve: ECCCurve::Ed25519,
                        q,
                    },
                    types::EncryptedSecretParams::new_plaintext(data, Some(checksum)),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use composed::Deserializable;

    #[test]
    fn test_key_gen_rsa_2048() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_create_certificates(true)
            .can_sign(true)
            .primary_user_id("Me <me@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(vec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(vec![
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA224,
                HashAlgorithm::SHA1,
            ])
            .preferred_compression_algorithms(vec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Rsa(2048))
                    .can_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate()
            .expect("failed to generate secret key");

        let signed_key = key.sign(|| "".into()).expect("failed to sign key");

        let armor = signed_key
            .to_armored_string()
            .expect("failed to serialize key");

        ::std::fs::write("sample-rsa.sec.asc", &armor).unwrap();

        let signed_key2 = SignedSecretKey::from_string(&armor).expect("failed to parse key");
        // assert_eq!(signed_key, signed_key2);
    }

    #[test]
    fn test_key_gen_x25519() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSA)
            .can_create_certificates(true)
            .can_sign(true)
            .primary_user_id("Me <me@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(vec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(vec![
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA224,
                HashAlgorithm::SHA1,
            ])
            .preferred_compression_algorithms(vec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                // TODO: this is the part that gpg is unhappy about
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH)
                    .can_encrypt(true)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate()
            .expect("failed to generate secret key");

        let signed_key = key.sign(|| "".into()).expect("failed to sign key");

        let armor = signed_key
            .to_armored_string()
            .expect("failed to serialize key");

        ::std::fs::write("sample-x25519.sec.asc", &armor).unwrap();

        let signed_key2 = SignedSecretKey::from_string(&armor).expect("failed to parse key");
        // assert_eq!(signed_key, signed_key2);
    }
}
