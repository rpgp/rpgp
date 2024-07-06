mod public;

pub use self::public::{PublicKey, PublicSubkey};

impl_secret_key!(SecretKey, crate::types::Tag::SecretKey, PublicKey);
impl_secret_key!(SecretSubkey, crate::types::Tag::SecretSubkey, PublicSubkey);
