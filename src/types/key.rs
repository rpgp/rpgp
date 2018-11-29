use errors::Result;
use ser::Serialize;
use types::KeyId;

pub trait KeyTrait: Serialize {
    fn fingerprint(&self) -> Vec<u8>;

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> Option<KeyId>;

    /// Verifies all components.
    fn verify(&self) -> Result<()>;
}

impl<'a, T: KeyTrait> KeyTrait for &'a T {
    fn fingerprint(&self) -> Vec<u8> {
        (*self).fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> Option<KeyId> {
        (*self).key_id()
    }

    /// Verifies all components.
    fn verify(&self) -> Result<()> {
        (*self).verify()
    }
}
