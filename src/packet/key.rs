mod public;
mod secret;
pub(crate) mod symmetric;

#[cfg(feature = "draft-ietf-openpgp-persistent-symmetric-keys")]
pub use symmetric::{
    PersistentSymmetricEncryptionKey, PersistentSymmetricKey, PersistentSymmetricSigningKey,
    PersistentSymmetricVerifyingKey,
};

pub use self::{
    public::{PubKeyInner, PublicKey, PublicSubkey},
    secret::{SecretKey, SecretSubkey},
};
