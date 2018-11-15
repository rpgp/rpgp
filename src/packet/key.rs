use packet::types::Tag;

impl_public_key!(PublicKey, Tag::PublicKey);
impl_public_key!(PublicSubkey, Tag::PublicSubkey);

impl_secret_key!(SecretKey, Tag::SecretKey);
impl_secret_key!(SecretSubkey, Tag::SecretSubkey);
