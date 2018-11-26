#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            packet_version: $crate::types::Version,
            version: $crate::types::KeyVersion,
            algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
            created_at: chrono::DateTime<chrono::Utc>,
            expiration: Option<u16>,
            public_params: $crate::crypto::public_key::PublicParams,
        }

        impl $name {
            /// Parses a `PublicKeyKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::types::Version,
                input: &[u8],
            ) -> $crate::errors::Result<Self> {
                let (_, details) = $crate::packet::public_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params) = details;
                Ok($name {
                    packet_version,
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                })
            }

            pub fn packet_version(&self) -> $crate::types::Version {
                self.packet_version
            }
        }

        impl_key!($name);
    };
}
