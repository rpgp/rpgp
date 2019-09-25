use smallvec::SmallVec;

use crate::crypto::public_key::PublicKeyAlgorithm;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RevocationKey {
    pub class: RevocationKeyClass,
    pub algorithm: PublicKeyAlgorithm,
    pub fingerprint: SmallVec<[u8; 20]>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum RevocationKeyClass {
    Default = 0x80,
    Sensitive = 0x80 | 0x40,
}

impl RevocationKey {
    pub fn new(
        class: RevocationKeyClass,
        algorithm: PublicKeyAlgorithm,
        fingerprint: &[u8],
    ) -> Self {
        RevocationKey {
            class,
            algorithm,
            fingerprint: SmallVec::from_slice(fingerprint),
        }
    }
}
