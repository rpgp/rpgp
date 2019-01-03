use std::time::Duration;

use chrono;
use rand::OsRng;
use rsa::math::ModInverse;
use rsa::{self, PublicKey as PublicKeyTrait};

use composed::{
    SignedKeyDetails, SignedPublicKey, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey,
};
use crypto;
use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use errors;
use packet::{self, UserAttribute, UserId};
use types::{self, SecretKeyTrait};
use util::write_bignum_mpi;

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    primary_key: packet::PublicKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubKey>,
}

/// User facing interface to work with a secret key.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubKey>,
    secret_subkeys: Vec<SecretSubKey>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyDetails {
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicSubKey {
    key: packet::PublicSubkey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SecretSubKey {
    key: packet::SecretSubkey,
}

impl KeyDetails {
    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> errors::Result<SignedKeyDetails>
    where
        F: (FnOnce() -> String) + Clone,
    {
        Ok(SignedKeyDetails {
            revocation_signatures: Default::default(),
            direct_signatures: Default::default(),
            users: self
                .user_ids
                .iter()
                .map(|u| u.sign(key, key_pw.clone()))
                .collect::<errors::Result<Vec<_>>>()?,
            user_attributes: self
                .user_attributes
                .iter()
                .map(|u| u.sign(key, key_pw.clone()))
                .collect::<errors::Result<Vec<_>>>()?,
        })
    }
}

impl PublicKey {
    pub fn sign<F>(
        &self,
        sec_key: &mut impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedPublicKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        Ok(SignedPublicKey {
            primary_key: self.primary_key.clone(),
            details: self.details.sign(sec_key, key_pw.clone())?,
            public_subkeys: self
                .public_subkeys
                .iter()
                .map(|k| k.sign(sec_key, key_pw.clone()))
                .collect::<errors::Result<Vec<_>>>()?,
        })
    }
}

impl PublicSubKey {
    pub fn sign<F>(
        &self,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedPublicSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        Ok(SignedPublicSubKey {
            key: self.key.clone(),
            signatures: vec![self.key.sign(sec_key, key_pw)?],
        })
    }
}

impl SecretKey {
    pub fn sign<F>(&self, key_pw: F) -> errors::Result<SignedSecretKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        Ok(SignedSecretKey {
            primary_key: self.primary_key.clone(),
            details: self.details.sign(&self.primary_key, key_pw.clone())?,
            public_subkeys: self
                .public_subkeys
                .iter()
                .map(|k| k.sign(&self.primary_key, key_pw.clone()))
                .collect::<errors::Result<Vec<_>>>()?,
            secret_subkeys: self
                .secret_subkeys
                .iter()
                .map(|k| k.sign(&self.primary_key, key_pw.clone()))
                .collect::<errors::Result<Vec<_>>>()?,
        })
    }
}

impl SecretSubKey {
    pub fn sign<F>(
        &self,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> errors::Result<SignedSecretSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        Ok(SignedSecretSubKey {
            key: self.key.clone(),
            signatures: vec![self.key.sign(sec_key, key_pw)?],
        })
    }
}

#[derive(Debug, PartialEq, Eq, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct SecretKeyParams {
    key_type: KeyType,

    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: String,
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
                    return Err("Keys with less than 2048bits are considered insecure".to_string());
                }
            }
            _ => {}
        }

        if self.user_ids.is_none() {
            return Err("Please specify at least one User Id".to_string());
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
}

impl SecretKeyParams {
    pub fn generate(self) -> errors::Result<SecretKey> {
        let (public_params, secret_params) = self.key_type.generate(self.passphrase)?;
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
        Ok(SecretKey {
            primary_key,
            details: KeyDetails {
                user_ids: self
                    .user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect(),
                user_attributes: self.user_attributes,
            },
            public_subkeys: Default::default(),
            secret_subkeys: Default::default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    // bit size
    Rsa(usize),
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
        }
    }

    pub fn generate(
        &self,
        passphrase: String,
    ) -> errors::Result<(PublicParams, types::EncryptedSecretParams)> {
        match self {
            KeyType::Rsa(bit_size) => {
                let mut rng = OsRng::new().expect("no system rng available");
                let key = rsa::RSAPrivateKey::new(&mut rng, *bit_size)?;

                // TODO: encrypt with iterated and salted

                let p = &key.primes()[0];
                let q = &key.primes()[1];
                let u = p.clone().mod_inverse(q).expect("invalid prime");

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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use composed::Deserializable;
    use ser::Serialize;

    #[test]
    fn test_key_gen_rsa_2048() {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .user_id("Me <me@mail.com>")
            .passphrase("hello".into())
            .build()
            .unwrap();

        let key = key_params
            .generate()
            .expect("failed to generate secret key");
        println!("{:#?}", key);

        let signed_key = key.sign(|| "hello".into()).expect("failed to sign key");

        let armor = signed_key
            .to_armored_string()
            .expect("failed to serialize key");

        println!("{}", hex::encode(signed_key.to_bytes().unwrap()));
        ::std::fs::write("sample.asc", &armor).unwrap();

        // let signed_key2 = SignedSecretKey::from_string(&armor).expect("failed to parse key");
        // assert_eq!(signed_key, signed_key2);
    }
}
