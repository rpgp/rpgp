use chrono::prelude::*;
use num_bigint::BigUint;

use crypto::sym::SymmetricKeyAlgorithm;
use packet::packet_trait::Packet;
use packet::types::ecc_curve::ECCCurve;
use packet::types::{KeyVersion, PublicKeyAlgorithm, Tag};

#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            version: KeyVersion,
            algorithm: PublicKeyAlgorithm,
            created_at: DateTime<Utc>,
            expiration: Option<u16>,
            public_params: PublicParams,
        }

        impl Packet for $name {
            fn tag(&self) -> Tag {
                $tag
            }
        }

        /// Represent the public paramaters for the different algorithms.
        #[derive(Debug, PartialEq, Eq)]
        pub enum PublicParams {
            RSA {
                n: BigUint,
                e: BigUint,
            },
            DSA {
                p: BigUint,
                q: BigUint,
                g: BigUint,
                y: BigUint,
            },
            ECDSA {
                curve: ECCCurve,
                p: Vec<u8>,
            },
            ECDH {
                curve: ECCCurve,
                p: Vec<u8>,
                hash: HashAlgorithm,
                alg_sym: SymmetricKeyAlgorithm,
            },
            Elgamal {
                p: BigUint,
                g: BigUint,
                y: BigUint,
            },
            EdDSA {
                curve: ECCCurve,
                q: Vec<u8>,
            },
        }

        impl $name {
            pub fn new(
                version: KeyVersion,
                algorithm: PublicKeyAlgorithm,
                created_at: DateTime<Utc>,
                expiration: Option<u16>,
                public_params: PublicParams,
            ) -> $name {
                $name {
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                }
            }
        }

        impl_key!($name);
    };
}
