use num_enum::TryFromPrimitive;
#[cfg(test)]
use proptest::prelude::*;
use smallvec::SmallVec;

use crate::crypto::public_key::PublicKeyAlgorithm;

/// "Revocation key" signature subpacket (deprecated)
///
/// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key-deprecated>
///
/// This deprecated mechanism was intended to allow a specified key to issue revocations
/// for a key.
#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct RevocationKey {
    pub class: RevocationKeyClass,
    pub algorithm: PublicKeyAlgorithm,
    #[debug("{}", hex::encode(fingerprint))]
    #[cfg_attr(
        test,
        proptest(strategy = "prop::collection::vec(any::<u8>(), 20).prop_map(SmallVec::from_vec)")
    )]
    pub fingerprint: SmallVec<[u8; 20]>,
}

/// "Class" setting for a [`RevocationKey`] subpacket (deprecated)
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
