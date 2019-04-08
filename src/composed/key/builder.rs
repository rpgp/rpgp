use std::time::Duration;

use chrono::{self, SubsecRound};
use rand::thread_rng;
use smallvec::SmallVec;

use composed::{KeyDetails, SecretKey, SecretSubkey};
use crypto::{ecdh, eddsa, rsa, HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use errors::Result;
use packet::{self, KeyFlags, UserAttribute, UserId};
use types::{self, CompressionAlgorithm, PublicParams, RevocationKey};

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
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    #[builder(default)]
    revocation_key: Option<RevocationKey>,

    #[builder]
    primary_user_id: String,

    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
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
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    packet_version: types::Version,
    #[builder(default)]
    version: types::KeyVersion,
    #[builder(default)]
    expiration: Option<Duration>,
}

impl SecretKeyParamsBuilder {
    fn validate(&self) -> std::result::Result<(), String> {
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
    pub fn generate(self) -> Result<SecretKey> {
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

        Ok(SecretKey::new(
            primary_key,
            KeyDetails::new(
                UserId::from_str(Default::default(), &self.primary_user_id),
                self.user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect(),
                self.user_attributes,
                keyflags,
                self.preferred_symmetric_algorithms,
                self.preferred_hash_algorithms,
                self.preferred_compression_algorithms,
                self.revocation_key,
            ),
            Default::default(),
            self.subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let (public_params, secret_params) = subkey.key_type.generate(passphrase)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_certify(subkey.can_create_certificates);
                    keyflags.set_encrypt_comms(subkey.can_encrypt);
                    keyflags.set_encrypt_storage(subkey.can_encrypt);
                    keyflags.set_sign(subkey.can_sign);

                    Ok(SecretSubkey::new(
                        packet::SecretSubkey {
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
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Encryption & Signing with RSA an the given bitsize.
    Rsa(u32),
    /// Encrypting with Curve25519
    ECDH,
    /// Signing with Curve25519
    EdDSA,
}

impl KeyType {
    pub fn to_alg(self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH => PublicKeyAlgorithm::ECDH,
            KeyType::EdDSA => PublicKeyAlgorithm::EdDSA,
        }
    }

    pub fn generate(
        self,
        passphrase: Option<String>,
    ) -> Result<(PublicParams, types::SecretParams)> {
        let mut rng = thread_rng();

        let (pub_params, plain) = match self {
            KeyType::Rsa(bit_size) => rsa::generate_key(&mut rng, bit_size as usize)?,
            KeyType::ECDH => ecdh::generate_key(&mut rng),
            KeyType::EdDSA => eddsa::generate_key(&mut rng),
        };

        let secret = match passphrase {
            Some(passphrase) => {
                // TODO: make configurable
                let s2k = types::StringToKey::new_default(&mut rng);
                let alg = SymmetricKeyAlgorithm::AES256;
                // encrypted, sha1 checksum
                let id = 254;

                // TODO: derive from key itself
                let version = types::KeyVersion::default();

                types::SecretParams::Encrypted(plain.encrypt(
                    &mut rng,
                    &passphrase,
                    alg,
                    s2k,
                    version,
                    id,
                )?)
            }
            None => types::SecretParams::Plain(plain),
        };

        Ok((pub_params, secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use composed::{Deserializable, SignedPublicKey, SignedSecretKey};
    use types::SecretKeyTrait;

    #[test]
    #[ignore] // slow in debug mode
    fn test_key_gen_rsa_2048() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_create_certificates(true)
            .can_sign(true)
            .primary_user_id("Me <me@mail.com>".into())
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::SHA2_256,
                HashAlgorithm::SHA2_384,
                HashAlgorithm::SHA2_512,
                HashAlgorithm::SHA2_224,
                HashAlgorithm::SHA1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ]);

        let key_params_enc = key_params
            .clone()
            .passphrase(Some("hello".into()))
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Rsa(2048))
                    .passphrase(Some("hello".into()))
                    .can_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let key_enc = key_params_enc
            .generate()
            .expect("failed to generate secret key, encrypted");

        let key_params_plain = key_params
            .clone()
            .passphrase(None)
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Rsa(2048))
                    .can_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let key_plain = key_params_plain
            .generate()
            .expect("failed to generate secret key");

        let signed_key_enc = key_enc.sign(|| "hello".into()).expect("failed to sign key");
        let signed_key_plain = key_plain.sign(|| "".into()).expect("failed to sign key");

        let armor_enc = signed_key_enc
            .to_armored_string(None)
            .expect("failed to serialize key");
        let armor_plain = signed_key_plain
            .to_armored_string(None)
            .expect("failed to serialize key");

        // std::fs::write("sample-rsa-enc.sec.asc", &armor_enc).unwrap();
        // std::fs::write("sample-rsa.sec.asc", &armor_plain).unwrap();

        let (signed_key2_enc, _headers) =
            SignedSecretKey::from_string(&armor_enc).expect("failed to parse key (enc)");
        signed_key2_enc.verify().expect("invalid key (enc)");

        let (signed_key2_plain, _headers) =
            SignedSecretKey::from_string(&armor_plain).expect("failed to parse key (plain)");
        signed_key2_plain.verify().expect("invalid key (plain)");

        signed_key2_enc
            .unlock(|| "hello".into(), |_| Ok(()))
            .expect("failed to unlock parsed key (enc)");
        signed_key2_plain
            .unlock(|| "".into(), |_| Ok(()))
            .expect("failed to unlock parsed key (plain)");

        assert_eq!(signed_key_plain, signed_key2_plain);

        let public_key = signed_key_plain.public_key();

        let public_signed_key = public_key
            .sign(&signed_key_plain, || "".into())
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None)
            .expect("failed to serialize public key");

        // std::fs::write("sample-rsa.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    #[test]
    fn test_key_gen_x25519() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSA)
            .can_create_certificates(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-x25519@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::SHA2_256,
                HashAlgorithm::SHA2_384,
                HashAlgorithm::SHA2_512,
                HashAlgorithm::SHA2_224,
                HashAlgorithm::SHA1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
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
            .to_armored_string(None)
            .expect("failed to serialize key");

        // std::fs::write("sample-x25519.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_key = signed_key.public_key();

        let public_signed_key = public_key
            .sign(&signed_key, || "".into())
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None)
            .expect("failed to serialize public key");

        // std::fs::write("sample-x25519.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }
}
