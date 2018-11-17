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
                let (_, pk) = $crate::packet::public_key_parser::parse(input)?;

                Ok(pk.into())
            }

            pub fn new(
                version: $crate::types::KeyVersion,
                algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
                created_at: chrono::DateTime<chrono::Utc>,
                expiration: Option<u16>,
                public_params: $crate::crypto::public_key::PublicParams,
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
