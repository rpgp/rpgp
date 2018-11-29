use crypto::hash::HashAlgorithm;
use errors::Result;
use types::KeyTrait;

pub trait PublicKeyTrait: KeyTrait {
    /// Verify a signed message.
    /// Data will be hashed using `hash`, before verifying.
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Vec<u8>]) -> Result<()>;
}
