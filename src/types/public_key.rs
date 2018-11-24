use crypto::hash::HashAlgorithm;
use errors::Result;

pub trait PublicKeyTrait {
    /// Verify a signed message.
    /// Data will be hashed using `hash`, before verifying.
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &[u8]) -> Result<()>;
}
