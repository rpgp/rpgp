use crypto::public_key::PublicKeyAlgorithm;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RevocationKey {
    pub class: u8,
    pub algorithm: PublicKeyAlgorithm,
    pub fingerprint: [u8; 20],
}
