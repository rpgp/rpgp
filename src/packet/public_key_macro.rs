#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            version: $crate::types::KeyVersion,
            algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
            created_at: chrono::DateTime<chrono::Utc>,
            expiration: Option<u16>,
            public_params: $crate::crypto::public_key::PublicParams,
        }

        impl $name {
            /// Parses a `PublicKeyKey` packet from the given slice.
            pub fn from_slice(input: &[u8]) -> $crate::errors::Result<Self> {
                let (_, details) = $crate::packet::public_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params) = details;
                Ok($name {
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                })
            }
        }

        impl_key!($name);
    };
}
