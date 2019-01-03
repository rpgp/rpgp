use crypto::public_key::PublicKeyAlgorithm;
use ser::Serialize;
use types::KeyId;

pub trait KeyTrait: Serialize + ::std::fmt::Debug {
    fn fingerprint(&self) -> Vec<u8>;

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> Option<KeyId>;

    fn algorithm(&self) -> PublicKeyAlgorithm;
}

impl<'a, T: KeyTrait> KeyTrait for &'a T {
    fn fingerprint(&self) -> Vec<u8> {
        (*self).fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> Option<KeyId> {
        (*self).key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (*self).algorithm()
    }
}
