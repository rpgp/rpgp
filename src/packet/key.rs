impl_public_key!(PublicKey, crate::types::Tag::PublicKey);
impl_public_key!(PublicSubkey, crate::types::Tag::PublicSubkey);

impl_secret_key!(SecretKey, crate::types::Tag::SecretKey, PublicKey);
impl_secret_key!(SecretSubkey, crate::types::Tag::SecretSubkey, PublicSubkey);
