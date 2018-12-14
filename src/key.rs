use std::time::Duration;

use chrono;
use rand::OsRng;
use rsa::{self, PublicKey as PublicKeyTrait};

use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use errors;
use packet::{self, UserAttribute, UserId};
use types;
use util::write_bignum_mpi;

/// User facing interface to work with a public key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    primary_key: packet::PublicKey,
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    public_subkeys: Vec<PublicKey>,
    secret_subkeys: Vec<SecretKey>,
}

/// User facing interface to work with a secret key.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    user_ids: Vec<UserId>,
    user_attributes: Vec<UserAttribute>,
    public_subkeys: Vec<PublicKey>,
    secret_subkeys: Vec<SecretKey>,
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
            user_ids: self
                .user_ids
                .iter()
                .map(|m| UserId::from_str(Default::default(), m))
                .collect(),
            user_attributes: self.user_attributes,
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

                let mut data = Vec::new();
                write_bignum_mpi(key.d(), &mut data)?;
                write_bignum_mpi(&key.primes()[0], &mut data)?;
                write_bignum_mpi(&key.primes()[1], &mut data)?;

                Ok((
                    PublicParams::RSA {
                        n: key.n().clone(),
                        e: key.e().clone(),
                    },
                    types::EncryptedSecretParams::new_plaintext(data, None),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen_rsa_2048() {
        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .user_id("Me <me@mail.com>")
            .passphrase("hello".into())
            .build()
            .unwrap();

        let key = key_params.generate().unwrap();

        println!("{:#?}", key);
    }
}
