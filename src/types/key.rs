use types::KeyId;

pub trait KeyTrait {
    fn fingerprint(&self) -> Vec<u8>;
    fn key_id(&self) -> Option<KeyId>;
}
