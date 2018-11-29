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

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_u16::<BigEndian>(
                    self.expiration
                        .expect("old key versions have an expiration"),
                )?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }
        }

        impl $crate::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> $crate::errors::Result<()> {
                writer.write_all(&[self.version as u8])?;

                match self.version {
                    $crate::types::KeyVersion::V2 | $crate::types::KeyVersion::V3 => {
                        self.to_writer_old(writer)
                    }
                    $crate::types::KeyVersion::V4 => self.to_writer_new(writer),
                }
            }
        }

        impl_key!($name);
    };
}
